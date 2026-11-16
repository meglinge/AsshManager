import express, {
  type Request,
  type Response,
  type NextFunction,
} from "express";
import helmet from "helmet";
import { rateLimit } from "express-rate-limit";
import { randomUUID } from "node:crypto";
import { resolve } from "node:path";
import { z, ZodError } from "zod";
import { Store, type Device, type User } from "./store.js";
import {
  type Actor,
  HttpError,
  access,
  assertActive,
  audit,
  emailVerificationRequired,
  encrypt,
  hash,
  now,
  passwordHash,
  passwordMatches,
  publicDevice,
  requireDevice,
  requireTeamAdmin,
  secret,
  teamRole,
} from "./security.js";
import { SSHService, operationSchema } from "./ssh.js";
import { mountMcp } from "./mcp.js";
import type { Mailer } from "./mail.js";
import { mountInvitations } from "./invitations.js";

const email = z
  .email()
  .max(254)
  .transform((v) => v.toLowerCase());
const name = z.string().trim().min(1).max(80);
const password = z.string().min(12, "密码至少 12 位").max(128);
const deviceSchema = z.object({
  name,
  team_id: z.string().uuid().nullable().default(null),
  host: z
    .string()
    .trim()
    .min(1)
    .max(253)
    .regex(/^[a-zA-Z0-9.:_-]+$/, "请输入主机名或 IP，不包含协议和路径"),
  port: z.number().int().min(1).max(65535).default(22),
  username: z.string().trim().min(1).max(128),
  note: z.string().max(1000).default(""),
  fingerprint: z
    .string()
    .regex(/^SHA256:[A-Za-z0-9+/]{43}$/, "请输入有效的 SHA256 SSH 主机指纹"),
  auth_type: z.enum(["password", "key"]),
  password: z.string().min(1).max(1024).optional(),
  privateKey: z.string().min(1).max(32768).optional(),
  passphrase: z.string().max(1024).optional(),
});
type AppOptions = {
  store: Store;
  key: Buffer;
  publicUrl: string;
  mailer: Mailer;
  allowedCidrs?: string[];
  trustProxy?: boolean;
  serveStatic?: boolean;
};

export function createApp({
  store,
  key,
  publicUrl,
  mailer,
  allowedCidrs = [],
  trustProxy = false,
  serveStatic = true,
}: AppOptions) {
  const app = express();
  const origin = new URL(publicUrl).origin;
  if (trustProxy) app.set("trust proxy", 1);
  app.disable("x-powered-by");
  app.use(
    helmet({
      contentSecurityPolicy: {
        directives: {
          "script-src": ["'self'"],
          "style-src": ["'self'", "'unsafe-inline'"],
          "connect-src": ["'self'"],
          "upgrade-insecure-requests": null,
        },
      },
      crossOriginEmbedderPolicy: false,
    }),
  );
  app.use(["/api", "/mcp"], (req, res, next) => {
    res.setHeader("Cache-Control", "no-store");
    const requestOrigin = req.get("origin");
    if (
      (requestOrigin && requestOrigin !== origin) ||
      req.get("sec-fetch-site") === "cross-site"
    )
      return next(new HttpError(403, "不允许跨站请求"));
    if (
      req.baseUrl !== "/mcp" &&
      !["GET", "HEAD", "OPTIONS"].includes(req.method) &&
      !requestOrigin
    )
      return next(new HttpError(403, "请求缺少 Origin"));
    next();
  });
  app.use(
    ["/api", "/mcp"],
    rateLimit({
      windowMs: 60000,
      limit: 240,
      standardHeaders: "draft-8",
      legacyHeaders: false,
      message: { error: "请求过于频繁，请稍后重试" },
    }),
  );
  app.use(express.json({ limit: "128kb" }));
  app.get("/healthz", (_req, res) => res.json({ ok: true }));
  app.get("/api/public-config", (_req, res) =>
    res.json({
      mailMode: mailer.mode,
      emailVerificationRequired: emailVerificationRequired(),
    }),
  );
  const authLimit = rateLimit({
    windowMs: 15 * 60000,
    limit: 30,
    standardHeaders: "draft-8",
    legacyHeaders: false,
    message: { error: "认证尝试过于频繁，请 15 分钟后重试" },
  });
  const actor = (res: Response) => res.locals.actor as Actor;
  const session = (res: Response, userId: string) => {
    const value = secret();
    store.run("DELETE FROM sessions WHERE expires_at<?", now());
    store.run(
      "INSERT INTO sessions(hash,user_id,expires_at) VALUES(?,?,?)",
      hash(value),
      userId,
      new Date(Date.now() + 7 * 86400000).toISOString(),
    );
    res.cookie("assh_session", value, {
      httpOnly: true,
      sameSite: "strict",
      secure: origin.startsWith("https:"),
      maxAge: 7 * 86400000,
      path: "/",
    });
    return { id: userId, source: "web" as const, sessionHash: hash(value) };
  };
  const safeUser = (user: User) => ({
    id: user.id,
    name: user.name,
    email: user.email,
    email_verified: !!user.email_verified_at,
  });
  const revokeAccess = (userId: string) => {
    store.run("DELETE FROM sessions WHERE user_id=?", userId);
    store.run("DELETE FROM email_tokens WHERE user_id=?", userId);
    store.run(
      "UPDATE tokens SET revoked_at=? WHERE user_id=? AND revoked_at IS NULL",
      now(),
      userId,
    );
  };
  const sendAccountMail = async (user: User, purpose: "verify" | "reset") => {
    const recent = store.get(
      "SELECT hash FROM email_tokens WHERE user_id=? AND purpose=? AND created_at>?",
      user.id,
      purpose,
      new Date(Date.now() - 60000).toISOString(),
    );
    if (recent) return;
    const token = secret();
    store.run(
      "DELETE FROM email_tokens WHERE expires_at<=? OR (user_id=? AND purpose=?)",
      now(),
      user.id,
      purpose,
    );
    store.run(
      "INSERT INTO email_tokens(hash,user_id,purpose,created_at,expires_at) VALUES(?,?,?,?,?)",
      hash(token),
      user.id,
      purpose,
      now(),
      new Date(
        Date.now() + (purpose === "verify" ? 86400000 : 1800000),
      ).toISOString(),
    );
    const link = `${origin}/#${new URLSearchParams({ action: purpose, token })}`;
    try {
      await mailer.send({
        to: user.email,
        subject:
          purpose === "verify"
            ? "验证你的 AsshManager 邮箱"
            : "重置 AsshManager 密码",
        text: `${purpose === "verify" ? "请验证邮箱并设置你自己的登录密码（24 小时内有效）。" : "请设置新的登录密码（30 分钟内有效）。"}\n\n${link}\n\n如果不是你发起的请求，请忽略此邮件。链接只能使用一次，请勿转发。`,
      });
    } catch {
      store.run("DELETE FROM email_tokens WHERE hash=?", hash(token));
      // Never log the transport error: it can include recipient, credentials or link.
      console.error("Account email delivery failed");
    }
  };
  const mailAccepted = {
    ok: true,
    message:
      "如果该邮箱符合条件，邮件将发送至该地址；请检查收件箱与垃圾邮件。可在一分钟后重试。",
  };
  app.post("/api/auth/register", authLimit, async (req, res) => {
    const data = z.object({ name, email }).parse(req.body);
    if (process.env.REGISTRATION_ENABLED === "false")
      throw new HttpError(403, "当前未开放注册");
    const requiresVerification = emailVerificationRequired();
    // In verified mode, only the mailbox owner may choose the password.
    const initialPassword = await passwordHash(
      requiresVerification ? secret() : password.parse(req.body.password),
    );
    let user = store.get<User>("SELECT * FROM users WHERE email=?", data.email);
    if (user && !requiresVerification)
      throw new HttpError(409, "注册失败，请尝试登录或找回密码");
    if (!user) {
      user = {
        ...data,
        id: randomUUID(),
        password: initialPassword,
        email_verified_at: null,
      };
      store.run(
        "INSERT INTO users(id,name,email,password) VALUES(?,?,?,?)",
        user.id,
        user.name,
        user.email,
        user.password,
      );
      audit(
        store,
        { id: user.id, source: "web" },
        "account.register",
        user.name,
      );
    }
    if (!requiresVerification) {
      session(res, user.id);
      res.status(201).json(safeUser(user));
      return;
    }
    if (!user.email_verified_at) await sendAccountMail(user, "verify");
    res.status(201).json(mailAccepted);
  });
  for (const [route, purpose] of [
    ["verification", "verify"],
    ["forgot-password", "reset"],
  ] as const) {
    app.post(`/api/auth/${route}`, authLimit, async (req, res) => {
      const data = z.object({ email }).parse(req.body);
      const user = store.get<User>(
        "SELECT * FROM users WHERE email=?",
        data.email,
      );
      if (user && (purpose === "reset" || !user.email_verified_at))
        await sendAccountMail(user, purpose);
      res.json(mailAccepted);
    });
  }
  for (const purpose of ["verify", "reset"] as const) {
    app.post(`/api/auth/${purpose}`, authLimit, async (req, res) => {
      const data = z
        .object({ token: z.string().length(43), password })
        .parse(req.body);
      const tokenHash = hash(data.token);
      const find = () =>
        store.get<{ user_id: string }>(
          "SELECT user_id FROM email_tokens WHERE hash=? AND purpose=? AND expires_at>?",
          tokenHash,
          purpose,
          now(),
        );
      if (!find())
        throw new HttpError(400, "链接已失效或已使用，请重新申请邮件");
      const hashed = await passwordHash(data.password);
      const userId = store.transaction(() => {
        const token = find(); // Recheck expiry and consumption after asynchronous scrypt.
        if (!token)
          throw new HttpError(400, "链接已失效或已使用，请重新申请邮件");
        store.run(
          "UPDATE users SET password=?,email_verified_at=COALESCE(email_verified_at,?) WHERE id=?",
          hashed,
          now(),
          token.user_id,
        );
        revokeAccess(token.user_id);
        audit(
          store,
          { id: token.user_id, source: "web" },
          `account.${purpose}`,
          "邮箱账号",
        );
        return token.user_id;
      });
      if (purpose === "verify") {
        session(res, userId);
        res.json(
          safeUser(store.get<User>("SELECT * FROM users WHERE id=?", userId)!),
        );
      } else res.json({ ok: true });
    });
  }
  app.post("/api/auth/login", authLimit, async (req, res) => {
    const data = z
      .object({ email, password: z.string().max(128) })
      .parse(req.body);
    const user = store.get<User>(
      "SELECT * FROM users WHERE email=?",
      data.email,
    );
    // Equal-cost verification for unknown users, without keeping a shared password.
    const valid = await passwordMatches(
      data.password,
      user?.password ?? `${"00".repeat(16)}:${"00".repeat(64)}`,
    );
    if (!user || !valid) throw new HttpError(401, "邮箱或密码不正确");
    if (
      store.get<User>("SELECT password FROM users WHERE id=?", user.id)
        ?.password !== user.password
    )
      throw new HttpError(401, "密码已变更，请重新登录");
    audit(store, session(res, user.id), "account.login", user.name);
    res.json(safeUser(user));
  });

  const ssh = new SSHService(store, key, allowedCidrs);
  mountMcp(app, store, ssh);
  app.use("/api", (req, res, next) => {
    const value = req.headers.cookie
      ?.split(";")
      .map((c) => c.trim())
      .find((c) => c.startsWith("assh_session="))
      ?.slice(13);
    const found =
      value &&
      store.get<{ user_id: string }>(
        "SELECT user_id FROM sessions WHERE hash=? AND expires_at>?",
        hash(value),
        now(),
      );
    if (!found) return next(new HttpError(401, "请先登录"));
    res.locals.actor = {
      id: found.user_id,
      source: "web",
      sessionHash: hash(value!),
    } satisfies Actor;
    next();
  });
  app.get("/api/me", (_req, res) =>
    res.json(
      safeUser(
        store.get<User>("SELECT * FROM users WHERE id=?", actor(res).id)!,
      ),
    ),
  );
  app.post("/api/auth/logout", (_req, res) => {
    store.run("DELETE FROM sessions WHERE hash=?", actor(res).sessionHash!);
    res.clearCookie("assh_session", {
      path: "/",
      secure: origin.startsWith("https:"),
      sameSite: "strict",
      httpOnly: true,
    });
    res.json({ ok: true });
  });
  app.use("/api", (_req, res, next) => {
    if (
      emailVerificationRequired() &&
      !store.get<User>(
        "SELECT email_verified_at FROM users WHERE id=?",
        actor(res).id,
      )?.email_verified_at
    )
      return next(new HttpError(403, "请先验证邮箱"));
    next();
  });
  mountInvitations(app, store, mailer, origin);
  app.post("/api/auth/password", async (req, res) => {
    const data = z
      .object({ current: z.string().max(128), password })
      .parse(req.body);
    const user = store.get<User>(
      "SELECT * FROM users WHERE id=?",
      actor(res).id,
    )!;
    if (!(await passwordMatches(data.current, user.password)))
      throw new HttpError(400, "当前密码不正确");
    const hashed = await passwordHash(data.password);
    assertActive(store, actor(res));
    store.transaction(() => {
      store.run("UPDATE users SET password=? WHERE id=?", hashed, user.id);
      revokeAccess(user.id);
      audit(store, actor(res), "account.password", user.name);
    });
    session(res, user.id);
    res.json({ ok: true });
  });
  app.get("/api/teams", (_req, res) =>
    res.json(
      store.all(
        "SELECT t.*,m.role,(SELECT count(*) FROM members x WHERE x.team_id=t.id) member_count FROM teams t JOIN members m ON m.team_id=t.id WHERE m.user_id=? ORDER BY t.created_at",
        actor(res).id,
      ),
    ),
  );
  app.post("/api/teams", (req, res) => {
    const data = z.object({ name }).parse(req.body);
    const id = randomUUID();
    store.transaction(() => {
      store.run(
        "INSERT INTO teams(id,name,created_at) VALUES(?,?,?)",
        id,
        data.name,
        now(),
      );
      store.run(
        "INSERT INTO members(team_id,user_id,role) VALUES(?,?,'owner')",
        id,
        actor(res).id,
      );
      audit(
        store,
        actor(res),
        "team.create",
        data.name,
        "success",
        undefined,
        "",
        id,
      );
    });
    res.status(201).json({ id, ...data, role: "owner" });
  });
  app.get("/api/teams/:id/members", (req, res) => {
    if (!teamRole(store, req.params.id, actor(res).id))
      throw new HttpError(404, "团队不存在");
    res.json(
      store.all(
        "SELECT u.id,u.name,u.email,m.role FROM members m JOIN users u ON u.id=m.user_id WHERE m.team_id=? ORDER BY u.name",
        req.params.id,
      ),
    );
  });
  app.delete("/api/teams/:id/members/:userId", (req, res) => {
    requireTeamAdmin(store, req.params.id, actor(res).id);
    const role = teamRole(store, req.params.id, req.params.userId);
    if (!role) throw new HttpError(404, "成员不存在");
    if (
      role === "owner" ||
      (role === "admin" &&
        teamRole(store, req.params.id, actor(res).id) !== "owner")
    )
      throw new HttpError(403, "不能移除所有者；管理员只能由所有者移除");
    const removed = store.get<{ name: string }>(
      "SELECT name FROM users WHERE id=?",
      req.params.userId,
    );
    store.transaction(() => {
      store.run(
        "DELETE FROM members WHERE team_id=? AND user_id=?",
        req.params.id,
        req.params.userId,
      );
      store.run(
        "DELETE FROM grants WHERE subject=? AND device_id IN (SELECT id FROM devices WHERE team_id=?)",
        req.params.userId,
        req.params.id,
      );
      store.run(
        "DELETE FROM invitations WHERE team_id=? AND invited_by=?",
        req.params.id,
        req.params.userId,
      );
      audit(
        store,
        actor(res),
        "team.member.remove",
        removed?.name ?? req.params.userId,
        "success",
        undefined,
        "",
        req.params.id,
      );
    });
    res.json({ ok: true });
  });

  app.get("/api/devices", (_req, res) =>
    res.json(
      store
        .all<Device>("SELECT * FROM devices ORDER BY created_at DESC")
        .filter((d) => access(store, d, actor(res).id))
        .map((d) => ({
          ...publicDevice(store, d, actor(res).id),
          connection: ssh.connection(d.id),
        })),
    ),
  );
  const saveDevice = (req: Request, res: Response, old?: Device) => {
    const data = deviceSchema.parse(req.body);
    if (old && data.team_id !== old.team_id)
      throw new HttpError(400, "不支持跨工作空间移动服务器，请新建服务器");
    if (data.team_id) requireTeamAdmin(store, data.team_id, actor(res).id);
    const id = old?.id ?? randomUUID();
    const changedCredential = !!(data.password || data.privateKey);
    if (
      (!old || changedCredential || old.auth_type !== data.auth_type) &&
      (data.auth_type === "key" ? !data.privateKey : !data.password)
    )
      throw new HttpError(400, "请提供 SSH 密码或私钥");
    const credential =
      changedCredential || !old
        ? encrypt(
            key,
            id,
            data.auth_type === "key"
              ? { privateKey: data.privateKey, passphrase: data.passphrase }
              : { password: data.password },
          )
        : old.credential;
    store.transaction(() => {
      if (old)
        store.run(
          "UPDATE devices SET name=?,host=?,port=?,username=?,note=?,fingerprint=?,credential=?,auth_type=?,status='unknown',checked_at=NULL WHERE id=?",
          data.name,
          data.host,
          data.port,
          data.username,
          data.note,
          data.fingerprint,
          credential,
          data.auth_type,
          id,
        );
      else
        store.run(
          "INSERT INTO devices(id,owner_id,team_id,name,host,port,username,note,fingerprint,credential,auth_type,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
          id,
          actor(res).id,
          data.team_id,
          data.name,
          data.host,
          data.port,
          data.username,
          data.note,
          data.fingerprint,
          credential,
          data.auth_type,
          now(),
        );
      audit(
        store,
        actor(res),
        old ? "device.update" : "device.create",
        data.name,
        "success",
        store.get<Device>("SELECT * FROM devices WHERE id=?", id),
      );
    });
    ssh.invalidate(id);
    res
      .status(old ? 200 : 201)
      .json(
        publicDevice(
          store,
          store.get<Device>("SELECT * FROM devices WHERE id=?", id)!,
          actor(res).id,
        ),
      );
  };
  app.post("/api/devices", (req, res) => saveDevice(req, res));
  app.put("/api/devices/:id", (req, res) =>
    saveDevice(
      req,
      res,
      requireDevice(store, actor(res), req.params.id, "manage"),
    ),
  );
  app.delete("/api/devices/:id", (req, res) => {
    const device = requireDevice(store, actor(res), req.params.id, "manage");
    store.transaction(() => {
      audit(store, actor(res), "device.delete", device.name, "success", device);
      store.run("DELETE FROM devices WHERE id=?", device.id);
    });
    ssh.invalidate(device.id);
    res.json({ ok: true });
  });
  app.get("/api/devices/:id/grants", (req, res) => {
    const device = requireDevice(store, actor(res), req.params.id, "manage");
    res.json(
      store.all(
        "SELECT subject,level FROM grants WHERE device_id=?",
        device.id,
      ),
    );
  });
  app.put("/api/devices/:id/grants", (req, res) => {
    const device = requireDevice(store, actor(res), req.params.id, "manage");
    if (!device.team_id)
      throw new HttpError(
        400,
        "个人服务器不提供共享授权，请在团队中创建服务器",
      );
    const grants = z
      .array(
        z.object({
          subject: z.union([z.literal("*"), z.string().uuid()]),
          level: z.enum(["view", "execute"]),
        }),
      )
      .max(1000)
      .parse(req.body);
    if (new Set(grants.map((g) => g.subject)).size !== grants.length)
      throw new HttpError(400, "授权主体重复");
    for (const grant of grants)
      if (
        grant.subject !== "*" &&
        !teamRole(store, device.team_id, grant.subject)
      )
        throw new HttpError(400, "只能授权给当前团队成员");
    store.transaction(() => {
      store.run("DELETE FROM grants WHERE device_id=?", device.id);
      for (const grant of grants)
        store.run(
          "INSERT INTO grants(device_id,subject,level) VALUES(?,?,?)",
          device.id,
          grant.subject,
          grant.level,
        );
      audit(
        store,
        actor(res),
        "device.permissions",
        device.name,
        "success",
        device,
        JSON.stringify(grants),
      );
    });
    res.json({ ok: true });
  });
  app.post("/api/devices/:id/run", async (req, res) =>
    res.json(
      await ssh.run(actor(res), req.params.id, operationSchema.parse(req.body)),
    ),
  );
  app.get("/api/tokens", (_req, res) =>
    res.json(
      store.all(
        "SELECT id,name,prefix,scope,expires_at,created_at,last_used_at,revoked_at FROM tokens WHERE user_id=? ORDER BY created_at DESC",
        actor(res).id,
      ),
    ),
  );
  app.post("/api/tokens", (req, res) => {
    const data = z
      .object({
        name,
        scope: z.enum(["read", "execute"]),
        days: z.number().int().min(1).max(90).default(30),
      })
      .parse(req.body);
    const token = `assh_${secret()}`;
    const id = randomUUID();
    const expires_at = new Date(
      Date.now() + data.days * 86400000,
    ).toISOString();
    store.transaction(() => {
      store.run(
        "INSERT INTO tokens(id,user_id,name,hash,prefix,scope,expires_at,created_at) VALUES(?,?,?,?,?,?,?,?)",
        id,
        actor(res).id,
        data.name,
        hash(token),
        token.slice(0, 12),
        data.scope,
        expires_at,
        now(),
      );
      audit(
        store,
        actor(res),
        "token.create",
        data.name,
        "success",
        undefined,
        data.scope,
      );
    });
    res.status(201).json({ id, token, expires_at });
  });
  app.delete("/api/tokens/:id", (req, res) => {
    const token = store.get<{ name: string }>(
      "SELECT name FROM tokens WHERE id=? AND user_id=? AND revoked_at IS NULL",
      req.params.id,
      actor(res).id,
    );
    if (!token) throw new HttpError(404, "令牌不存在或已撤销");
    store.transaction(() => {
      store.run(
        "UPDATE tokens SET revoked_at=? WHERE id=?",
        now(),
        req.params.id,
      );
      audit(store, actor(res), "token.revoke", token.name);
    });
    res.json({ ok: true });
  });
  app.get("/api/audit", (req, res) => {
    const { team, before } = z
      .object({
        team: z.string().uuid().optional(),
        before: z.coerce
          .number()
          .int()
          .positive()
          .default(Number.MAX_SAFE_INTEGER),
      })
      .parse(req.query);
    if (team) requireTeamAdmin(store, team, actor(res).id);
    res.json(
      store.all(
        `SELECT a.*,u.name actor_name FROM audit a JOIN users u ON u.id=a.actor_id WHERE ${team ? "a.team_id=?" : "a.actor_id=?"} AND a.id<? ORDER BY a.id DESC LIMIT 100`,
        team ?? actor(res).id,
        before,
      ),
    );
  });
  app.use("/api", (_req, _res, next) => next(new HttpError(404, "接口不存在")));
  if (serveStatic) {
    app.use(express.static(resolve("dist")));
    app.get("/{*path}", (_req, res) =>
      res.sendFile(resolve("dist/index.html")),
    );
  }
  app.use(
    (error: unknown, _req: Request, res: Response, _next: NextFunction) => {
      if (res.headersSent) return;
      if (error instanceof ZodError) {
        res.status(400).json({
          error: error.issues
            .map((i) => `${i.path.join(".")}: ${i.message}`)
            .join("；"),
        });
        return;
      }
      if (error instanceof HttpError) {
        res.status(error.status).json({ error: error.message });
        return;
      }
      if ((error as { type?: string })?.type === "entity.too.large") {
        res.status(413).json({ error: "请求内容过大" });
        return;
      }
      if (error instanceof SyntaxError) {
        res.status(400).json({ error: "请求 JSON 格式不正确" });
        return;
      }
      // Omit messages/request bodies: driver errors can contain user-supplied secrets.
      console.error("Unhandled request error", {
        name: (error as Error)?.name,
        code: (error as NodeJS.ErrnoException)?.code,
        stack: (error as Error)?.stack?.split("\n").slice(1).join("\n"),
      });
      res.status(500).json({ error: "服务暂时不可用，请稍后重试" });
    },
  );
  return Object.assign(app, { ssh });
}
