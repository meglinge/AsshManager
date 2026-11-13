import {
  createCipheriv,
  createDecipheriv,
  createHash,
  randomBytes,
  scrypt as scryptCallback,
  timingSafeEqual,
} from "node:crypto";
import { promisify } from "node:util";
import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import type { Store, Device, Token } from "./store.js";

const scrypt = promisify(scryptCallback);
export const now = () => new Date().toISOString();
export const emailVerificationRequired = () =>
  process.env.EMAIL_VERIFICATION_REQUIRED === "true";
export const hash = (value: string) =>
  createHash("sha256").update(value).digest("hex");
export const secret = () => randomBytes(32).toString("base64url");
export class HttpError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message);
  }
}
export async function passwordHash(password: string) {
  const salt = randomBytes(16).toString("hex");
  return `${salt}:${((await scrypt(password, salt, 64)) as Buffer).toString("hex")}`;
}
export async function passwordMatches(password: string, stored: string) {
  const [salt, expected] = stored.split(":");
  const actual = (await scrypt(password, salt, 64)) as Buffer;
  return timingSafeEqual(actual, Buffer.from(expected, "hex"));
}
export function loadKey(dataDir: string) {
  if (process.env.ENCRYPTION_KEY) {
    if (!/^[a-f\d]{64}$/i.test(process.env.ENCRYPTION_KEY))
      throw new Error("ENCRYPTION_KEY must be 64 hexadecimal characters");
    return Buffer.from(process.env.ENCRYPTION_KEY, "hex");
  }
  if (process.env.NODE_ENV === "production")
    throw new Error("Production requires ENCRYPTION_KEY");
  mkdirSync(dataDir, { recursive: true, mode: 0o700 });
  const path = join(dataDir, "development.key");
  try {
    return readFileSync(path);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
  }
  const key = randomBytes(32);
  writeFileSync(path, key, { mode: 0o600, flag: "wx" });
  return key;
}
export function encrypt(key: Buffer, deviceId: string, value: object) {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  cipher.setAAD(Buffer.from(deviceId));
  const body = Buffer.concat([
    cipher.update(JSON.stringify(value), "utf8"),
    cipher.final(),
  ]);
  return [iv, cipher.getAuthTag(), body]
    .map((v) => v.toString("base64"))
    .join(".");
}
export function decrypt(key: Buffer, deviceId: string, value: string) {
  const [iv, tag, body] = value.split(".").map((v) => Buffer.from(v, "base64"));
  const cipher = createDecipheriv("aes-256-gcm", key, iv);
  cipher.setAAD(Buffer.from(deviceId));
  cipher.setAuthTag(tag);
  return JSON.parse(
    Buffer.concat([cipher.update(body), cipher.final()]).toString(),
  ) as { password?: string; privateKey?: string; passphrase?: string };
}
export interface Actor {
  id: string;
  source: "web" | "mcp";
  sessionHash?: string;
  token?: Token;
}
export type Level = "view" | "execute" | "manage";
export function assertActive(store: Store, actor: Actor) {
  if (
    emailVerificationRequired() &&
    !store.get(
      "SELECT id FROM users WHERE id=? AND email_verified_at IS NOT NULL",
      actor.id,
    )
  )
    throw new HttpError(403, "请先验证邮箱");
  const valid =
    actor.source === "mcp"
      ? store.get<Token>(
          "SELECT * FROM tokens WHERE id=? AND revoked_at IS NULL AND expires_at>?",
          actor.token!.id,
          now(),
        )
      : store.get(
          "SELECT hash FROM sessions WHERE hash=? AND expires_at>?",
          actor.sessionHash!,
          now(),
        );
  if (!valid) throw new HttpError(401, "登录或令牌已失效，请重新认证");
}
export function teamRole(store: Store, team: string, user: string) {
  return store.get<{ role: string }>(
    "SELECT role FROM members WHERE team_id=? AND user_id=?",
    team,
    user,
  )?.role;
}
export function requireTeamAdmin(store: Store, team: string, user: string) {
  const role = teamRole(store, team, user);
  if (role !== "owner" && role !== "admin")
    throw new HttpError(403, "仅团队所有者或管理员可以执行此操作");
}
export function access(
  store: Store,
  device: Device,
  user: string,
): Level | null {
  if (!device.team_id) return device.owner_id === user ? "manage" : null;
  const role = teamRole(store, device.team_id, user);
  if (!role) return null;
  if (role === "owner" || role === "admin") return "manage";
  const grants = store.all<{ level: Level }>(
    "SELECT level FROM grants WHERE device_id=? AND subject IN (?,?)",
    device.id,
    user,
    "*",
  );
  if (grants.some((g) => g.level === "execute")) return "execute";
  return grants.length ? "view" : null;
}
export function requireDevice(
  store: Store,
  actor: Actor,
  id: string,
  level: Level,
) {
  assertActive(store, actor);
  const device = store.get<Device>("SELECT * FROM devices WHERE id=?", id);
  const granted = device && access(store, device, actor.id);
  if (!device || !granted)
    throw new HttpError(404, "服务器不存在或你没有访问权限");
  if (level === "manage" && granted !== "manage")
    throw new HttpError(403, "需要服务器管理权限");
  if (
    level === "execute" &&
    (granted === "view" || (actor.token && actor.token.scope !== "execute"))
  )
    throw new HttpError(403, "需要执行权限与可执行令牌");
  return device;
}
export function publicDevice(store: Store, device: Device, user: string) {
  const { credential: _credential, ...safe } = device;
  return { ...safe, access: access(store, device, user) };
}
export function audit(
  store: Store,
  actor: Actor,
  action: string,
  target: string,
  outcome = "success",
  device?: Device,
  detail = "",
  teamId?: string,
) {
  store.run(
    "INSERT INTO audit(actor_id,team_id,device_id,target,action,outcome,source,detail,created_at) VALUES(?,?,?,?,?,?,?,?,?)",
    actor.id,
    device?.team_id ?? teamId ?? null,
    device?.id ?? null,
    target,
    action,
    outcome,
    actor.source,
    detail,
    now(),
  );
}
