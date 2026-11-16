import { lookup } from "node:dns/promises";
import { createHash } from "node:crypto";
import { Client, type SFTPWrapper } from "ssh2";
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

// Changing any of these makes a pooled connection unusable for the device.
const signature = (d: Device) =>
  JSON.stringify([d.host, d.port, d.username, d.fingerprint, d.credential]);

type Pooled = {
  key: string;
  client: Client;
  ready: Promise<void>;
  sftp?: Promise<SFTPWrapper>;
  users: number;
  closed: boolean;
  connectedAt?: string;
  lastUsed: number;
  idle?: NodeJS.Timeout;
  aborts: Set<(error: unknown) => void>;
};

export type ConnectionState = {
  state: "connecting" | "connected";
  since: string | null;
  active: number;
};

export class SSHService {
  private active = new Map<string, number>();
  private pool = new Map<string, Pooled>();
  constructor(
    private store: Store,
    private key: Buffer,
    private allowedCidrs: string[] = [],
    private limits = { idleMs: 5 * 60_000, perDevice: 8, connections: 64 },
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
      const entry = await this.acquire(device);
      let result: unknown;
      try {
        result = await this.perform(entry, actor, device, op);
      } finally {
        this.release(entry);
      }
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
  connection(id: string): ConnectionState | null {
    const entry = this.pool.get(id);
    if (!entry) return null;
    return {
      state: entry.connectedAt ? "connected" : "connecting",
      since: entry.connectedAt ?? null,
      active: entry.users,
    };
  }
  // Call after a device is changed or deleted; drops its connection when it no longer matches.
  invalidate(id: string) {
    const entry = this.pool.get(id);
    const latest = this.store.get<Device>(
      "SELECT * FROM devices WHERE id=?",
      id,
    );
    if (entry && (!latest || signature(latest) !== entry.key))
      this.drop(entry, new HttpError(409, "服务器配置已更改，连接已关闭"));
  }
  close() {
    for (const entry of this.pool.values())
      this.drop(entry, new HttpError(503, "服务正在关闭"));
  }
  private async acquire(device: Device) {
    let entry = this.pool.get(device.id);
    if (entry && entry.key !== signature(device)) {
      this.drop(entry, new HttpError(409, "服务器配置已更改，连接已关闭"));
      entry = undefined;
    }
    if (!entry) {
      if (this.pool.size >= this.limits.connections) {
        const idle = [...this.pool.values()]
          .filter((e) => !e.users)
          .sort((a, b) => a.lastUsed - b.lastUsed)[0];
        if (!idle) throw new HttpError(429, "SSH 连接数已达上限，请稍后重试");
        this.drop(idle);
      }
      entry = this.open(device);
      this.pool.set(device.id, entry);
    }
    if (entry.users >= this.limits.perDevice)
      throw new HttpError(429, "此服务器的并发操作已达上限，请稍后重试");
    entry.users++;
    clearTimeout(entry.idle);
    try {
      await entry.ready;
    } catch (error) {
      this.release(entry);
      throw error;
    }
    return entry;
  }
  private release(entry: Pooled) {
    entry.users--;
    entry.lastUsed = Date.now();
    if (entry.users || entry.closed) return;
    entry.idle = setTimeout(() => this.drop(entry), this.limits.idleMs);
    entry.idle.unref();
  }
  private drop(entry: Pooled, reason?: unknown) {
    if (entry.closed) return;
    entry.closed = true;
    clearTimeout(entry.idle);
    for (const [id, e] of this.pool) if (e === entry) this.pool.delete(id);
    const error = reason ?? new HttpError(502, "SSH 连接意外关闭");
    for (const abort of entry.aborts) abort(error);
    entry.client.destroy();
  }
  private open(device: Device): Pooled {
    const client = new Client();
    const entry: Pooled = {
      key: signature(device),
      client,
      ready: Promise.resolve(),
      users: 0,
      closed: false,
      lastUsed: Date.now(),
      aborts: new Set(),
    };
    entry.ready = new Promise<void>((resolve, reject) => {
      const fail = (error: unknown) => {
        reject(error);
        this.drop(entry, error);
      };
      client.on("ready", () => {
        entry.connectedAt = now();
        resolve();
      });
      client.on("error", fail);
      client.on("close", () => fail(new HttpError(502, "SSH 连接意外关闭")));
      client.on("end", () => fail(new HttpError(502, "SSH 连接意外关闭")));
      resolveTarget(device.host, this.allowedCidrs)
        .then((address) => {
          if (entry.closed) return;
          const credentials = decrypt(this.key, device.id, device.credential);
          client.connect({
            host: address,
            port: device.port,
            username: device.username,
            ...credentials,
            readyTimeout: 10000,
            keepaliveInterval: 15000,
            keepaliveCountMax: 3,
            hostVerifier: (key: Buffer) => {
              const fingerprint = `SHA256:${createHash("sha256").update(key).digest("base64").replace(/=+$/, "")}`;
              if (fingerprint === device.fingerprint) return true;
              fail(new HttpError(502, "SSH 主机指纹不匹配，已拒绝连接"));
              return false;
            },
          });
        })
        .catch(fail);
    });
    entry.ready.catch(() => {});
    return entry;
  }
  private sftp(entry: Pooled) {
    entry.sftp ??= new Promise<SFTPWrapper>((resolve, reject) =>
      entry.client.sftp((error, sftp) => {
        if (error) {
          entry.sftp = undefined;
          return reject(error);
        }
        sftp.on("close", () => (entry.sftp = undefined));
        resolve(sftp);
      }),
    );
    return entry.sftp;
  }
  // Aborting one operation closes only its channel or stream; the shared connection stays up.
  private perform(
    entry: Pooled,
    actor: Actor,
    device: Device,
    op: Operation,
  ): Promise<unknown> {
    return new Promise((resolve, reject) => {
      let finished = false;
      let cleanup = () => {};
      const timeout = setTimeout(
        () =>
          done(
            new HttpError(
              504,
              "SSH 操作超时，已关闭本次操作通道；远程进程可能仍在运行",
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
          if (signature(latest) !== signature(device))
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
        entry.aborts.delete(done);
        cleanup();
        if (error) reject(error);
        else resolve(result);
      };
      entry.aborts.add(done);
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
        entry.client.exec(op.command, (error, channel) => {
          if (error) return done(error);
          cleanup = () => {
            try {
              channel.signal("KILL");
            } catch {}
            channel.close();
          };
          if (finished) return cleanup();
          const stdout: Buffer[] = [],
            stderr: Buffer[] = [];
          let bytes = 0;
          const append = (target: Buffer[], data: Buffer) => {
            bytes += data.length;
            if (bytes > 262144)
              return done(
                new HttpError(413, "命令输出超过 256 KiB，已关闭本次操作通道"),
              );
            target.push(Buffer.from(data));
          };
          channel.on("data", (data: Buffer) => append(stdout, data));
          channel.stderr.on("data", (data) => append(stderr, data));
          channel.on("error", (error: Error) => done(error));
          channel.on("close", (code: number | null, signal: string | null) => {
            cleanup = () => {};
            done(undefined, {
              stdout: Buffer.concat(stdout).toString(),
              stderr: Buffer.concat(stderr).toString(),
              exitCode: code ?? null,
              signal: signal ?? null,
            });
          });
        });
        return;
      }
      this.sftp(entry).then((sftp) => {
        if (finished) return;
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
          cleanup = () => stream.destroy();
          const chunks: Buffer[] = [];
          let bytes = 0;
          stream.on("data", (data: Buffer) => {
            bytes += data.length;
            if (bytes > 262144) {
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
          cleanup = () => stream.destroy();
          stream.on("error", (error: Error) => done(error));
          stream.on("close", () =>
            done(undefined, {
              written: true,
              bytes: Buffer.byteLength(op.content),
            }),
          );
          stream.end(op.content);
        }
      }, done);
    });
  }
}
