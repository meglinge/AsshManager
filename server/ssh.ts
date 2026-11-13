import { lookup } from "node:dns/promises";
import { createHash } from "node:crypto";
import { Client } from "ssh2";
import ipaddr from "ipaddr.js";
import { z } from "zod";
import type { Store, Device } from "./store.js";
import {
  type Actor,
  HttpError,
  audit,
  decrypt,
  hash,
  now,
  requireDevice,
} from "./security.js";

export const operationSchema = z.discriminatedUnion("operation", [
  z.object({ operation: z.literal("ping") }),
  z.object({
    operation: z.literal("execute"),
    command: z.string().min(1).max(8192),
    timeout: z.number().int().min(1).max(60).default(30),
  }),
  z.object({
    operation: z.literal("list_directory"),
    path: z
      .string()
      .min(1)
      .max(4096)
      .refine((p) => p.startsWith("/") && !p.includes("\0"), "需要绝对路径"),
  }),
  z.object({
    operation: z.literal("read_file"),
    path: z
      .string()
      .min(1)
      .max(4096)
      .refine((p) => p.startsWith("/") && !p.includes("\0"), "需要绝对路径"),
  }),
  z.object({
    operation: z.literal("write_file"),
    path: z
      .string()
      .min(1)
      .max(4096)
      .refine((p) => p.startsWith("/") && !p.includes("\0"), "需要绝对路径"),
    content: z.string().max(65536),
    overwrite: z.boolean().default(false),
  }),
]);
export type Operation = z.infer<typeof operationSchema>;

export async function resolveTarget(host: string, allowedCidrs: string[]) {
  const addresses = await lookup(host, { all: true, verbatim: true });
  if (!addresses.length) throw new HttpError(400, "无法解析 SSH 主机");
  for (const { address } of addresses) {
    const ip = ipaddr.process(address);
    const range = ip.range();
    // Metadata and multicast are never allowed, including when private networks are enabled.
    if (
      ["linkLocal", "multicast", "unspecified", "broadcast"].includes(range) ||
      ["100.100.100.200", "fd00:ec2::254"].includes(ip.toString())
    )
      throw new HttpError(400, "禁止访问此网络地址");
    const explicitlyAllowed = allowedCidrs.some((cidr) => {
      const [network, bits] = ipaddr.parseCIDR(cidr);
      return network.kind() === ip.kind() && ip.match(network, bits);
    });
    if (range !== "unicast" && !explicitlyAllowed)
      throw new HttpError(
        400,
        "此地址不在允许的 SSH 网络中；内网需由部署管理员配置",
      );
  }
  // Use the checked IP, not a second hostname lookup (DNS rebinding).
  return addresses[0].address;
}

export class SSHService {
  private active = new Map<string, number>();
  constructor(
    private store: Store,
    private key: Buffer,
    private allowedCidrs: string[] = [],
  ) {
    allowedCidrs.forEach((cidr) => ipaddr.parseCIDR(cidr));
  }
  async run(actor: Actor, id: string, input: Operation) {
    const op = operationSchema.parse(input);
    const level = op.operation === "ping" ? "view" : "execute";
    let device: Device;
    try {
      device = requireDevice(this.store, actor, id, level);
    } catch (error) {
      audit(this.store, actor, `ssh.${op.operation}`, id, "denied");
      throw error;
    }
    const current = this.active.get(actor.id) ?? 0;
    if (
      current >= 4 ||
      [...this.active.values()].reduce((a, b) => a + b, 0) >= 32
    )
      throw new HttpError(429, "SSH 并发连接已达上限，请稍后重试");
    const detail =
      op.operation === "execute" ? `command_sha256=${hash(op.command)}` : "";
    const started = Date.now();
    audit(
      this.store,
      actor,
      `ssh.${op.operation}`,
      device.name,
      "started",
      device,
      detail,
    );
    this.active.set(actor.id, current + 1);
    try {
      const result = await this.connect(actor, device, op);
      if (op.operation === "ping")
        this.store.run(
          "UPDATE devices SET status='online',checked_at=? WHERE id=?",
          now(),
          id,
        );
      const commandResult =
        op.operation === "execute"
          ? (result as { exitCode: number | null; signal: string | null })
          : undefined;
      audit(
        this.store,
        actor,
        `ssh.${op.operation}`,
        device.name,
        commandResult && commandResult.exitCode !== 0 ? "failed" : "success",
        device,
        `${detail} duration_ms=${Date.now() - started}${commandResult ? ` exit_code=${commandResult.exitCode} signal=${commandResult.signal}` : ""}`.trim(),
      );
      return result;
    } catch (error) {
      if (op.operation === "ping")
        this.store.run(
          "UPDATE devices SET status='failed',checked_at=? WHERE id=?",
          now(),
          id,
        );
      audit(
        this.store,
        actor,
        `ssh.${op.operation}`,
        device.name,
        "failed",
        device,
        `${detail} duration_ms=${Date.now() - started}`.trim(),
      );
      if (error instanceof HttpError) throw error;
      throw new HttpError(
        502,
        "SSH 连接或操作失败，请检查网络、认证信息及主机指纹",
      );
    } finally {
      const left = (this.active.get(actor.id) ?? 1) - 1;
      if (left) this.active.set(actor.id, left);
      else this.active.delete(actor.id);
    }
  }
  private connect(
    actor: Actor,
    device: Device,
    op: Operation,
  ): Promise<unknown> {
    return new Promise((resolve, reject) => {
      const client = new Client();
      let finished = false;
      const timeout = setTimeout(
        () =>
          done(
            new HttpError(
              504,
              "SSH 操作超时，连接已关闭；远程进程可能仍在运行",
            ),
          ),
        (op.operation === "execute" ? op.timeout : 20) * 1000,
      );
      const permissionCheck = setInterval(() => {
        try {
          const latest = requireDevice(
            this.store,
            actor,
            device.id,
            op.operation === "ping" ? "view" : "execute",
          );
          if (
            latest.credential !== device.credential ||
            latest.fingerprint !== device.fingerprint ||
            latest.host !== device.host ||
            latest.port !== device.port ||
            latest.username !== device.username
          )
            throw new HttpError(409, "服务器配置已更改，连接已关闭");
        } catch (error) {
          done(error);
        }
      }, 500);
      const done = (error?: unknown, result?: unknown) => {
        if (finished) return;
        finished = true;
        clearTimeout(timeout);
        clearInterval(permissionCheck);
        client.destroy();
        if (error) reject(error);
        else resolve(result);
      };
      client.on("error", (error) => done(error));
      client.on("close", () => done(new HttpError(502, "SSH 连接意外关闭")));
      client.on("ready", () => {
        try {
          requireDevice(
            this.store,
            actor,
            device.id,
            op.operation === "ping" ? "view" : "execute",
          );
        } catch (error) {
          done(error);
          return;
        }
        if (op.operation === "ping") {
          done(undefined, { connected: true, fingerprint: device.fingerprint });
          return;
        }
        if (op.operation === "execute") {
          client.exec(op.command, (error, channel) => {
            if (error) return done(error);
            const stdout: Buffer[] = [],
              stderr: Buffer[] = [];
            let bytes = 0;
            const append = (target: Buffer[], data: Buffer) => {
              bytes += data.length;
              if (bytes > 262144)
                return done(
                  new HttpError(413, "命令输出超过 256 KiB，连接已关闭"),
                );
              target.push(Buffer.from(data));
            };
            channel.on("data", (data: Buffer) => append(stdout, data));
            channel.stderr.on("data", (data) => append(stderr, data));
            channel.on("error", (error: Error) => done(error));
            channel.on("close", (code: number | null, signal: string | null) =>
              done(undefined, {
                stdout: Buffer.concat(stdout).toString(),
                stderr: Buffer.concat(stderr).toString(),
                exitCode: code ?? null,
                signal: signal ?? null,
              }),
            );
          });
          return;
        }
        client.sftp((error, sftp) => {
          if (error) return done(error);
          if (op.operation === "list_directory") {
            sftp.readdir(op.path, (error, files) => {
              if (error) return done(error);
              done(undefined, {
                entries: files.slice(0, 1000).map((f) => ({
                  name: f.filename,
                  size: f.attrs.size,
                  directory: f.attrs.isDirectory(),
                  modifiedAt: new Date(f.attrs.mtime * 1000).toISOString(),
                })),
                truncated: files.length > 1000,
              });
            });
          } else if (op.operation === "read_file") {
            const stream = sftp.createReadStream(op.path);
            const chunks: Buffer[] = [];
            let bytes = 0;
            stream.on("data", (data: Buffer) => {
              bytes += data.length;
              if (bytes > 262144) {
                stream.destroy();
                done(new HttpError(413, "文件超过 256 KiB 限制"));
                return;
              }
              chunks.push(Buffer.from(data));
            });
            stream.on("error", (error: Error) => done(error));
            stream.on("end", () =>
              done(undefined, {
                content: Buffer.concat(chunks).toString("utf8"),
                bytes,
              }),
            );
          } else {
            if (Buffer.byteLength(op.content) > 65536)
              return done(new HttpError(413, "写入内容超过 64 KiB 限制"));
            const stream = sftp.createWriteStream(op.path, {
              flags: op.overwrite ? "w" : "wx",
              mode: 0o600,
            });
            stream.on("error", (error: Error) => done(error));
            stream.on("close", () =>
              done(undefined, {
                written: true,
                bytes: Buffer.byteLength(op.content),
              }),
            );
            stream.end(op.content);
          }
        });
      });
      resolveTarget(device.host, this.allowedCidrs)
        .then((address) => {
          if (finished) return;
          const credentials = decrypt(this.key, device.id, device.credential);
          client.connect({
            host: address,
            port: device.port,
            username: device.username,
            ...credentials,
            readyTimeout: 10000,
            keepaliveInterval: 5000,
            hostVerifier: (key: Buffer) => {
              const fingerprint = `SHA256:${createHash("sha256").update(key).digest("base64").replace(/=+$/, "")}`;
              if (fingerprint !== device.fingerprint) {
                done(new HttpError(502, "SSH 主机指纹不匹配，已拒绝连接"));
                return false;
              }
              return true;
            },
          });
        })
        .catch((error) => done(error));
    });
  }
}
