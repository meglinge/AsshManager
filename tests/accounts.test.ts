import { test, type TestContext } from "node:test";
import assert from "node:assert/strict";
import { once } from "node:events";
import { randomBytes } from "node:crypto";
import { mkdtemp, readdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createApp } from "../server/app.js";
import { Store } from "../server/store.js";
import { hash, passwordHash } from "../server/security.js";
import { createMailer, type Mail, type Mailer } from "../server/mail.js";

const password = "Mailbox-owner-password-27";
async function fixture(
  t: TestContext,
  requireVerification = true,
  mailer?: Mailer,
) {
  const previous = process.env.EMAIL_VERIFICATION_REQUIRED;
  if (requireVerification) process.env.EMAIL_VERIFICATION_REQUIRED = "true";
  else delete process.env.EMAIL_VERIFICATION_REQUIRED;
  t.after(() => {
    if (previous === undefined) delete process.env.EMAIL_VERIFICATION_REQUIRED;
    else process.env.EMAIL_VERIFICATION_REQUIRED = previous;
  });
  const store = new Store(":memory:");
  const mail: Mail[] = [];
  let failMail = false;
  const origin = "http://localhost";
  const app = createApp({
    store,
    key: randomBytes(32),
    publicUrl: origin,
    serveStatic: false,
    mailer: mailer ?? {
      mode: "smtp",
      async send(message) {
        if (failMail) throw new Error("sensitive transport error");
        mail.push(message);
      },
    },
  });
  const server = app.listen(0, "127.0.0.1");
  await once(server, "listening");
  t.after(async () => {
    await new Promise<void>((resolve) => server.close(() => resolve()));
    store.db.close();
  });
  const base = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
  const request = async (
    path: string,
    body?: unknown,
    cookie = "",
    method = body === undefined ? "GET" : "POST",
    headers: Record<string, string> = {},
  ) => {
    const response = await fetch(base + path, {
      method,
      headers: {
        origin,
        cookie,
        "Content-Type": "application/json",
        ...headers,
      },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    return {
      status: response.status,
      body: await response.json(),
      cookie: response.headers.get("set-cookie")?.split(";")[0] ?? "",
    };
  };
  const token = () =>
    new URLSearchParams(
      new URL(mail.at(-1)!.text.match(/http:\/\/\S+/)![0]).hash.slice(1),
    ).get("token")!;
  const register = async (name: string) => {
    assert.equal(
      (
        await request("/api/auth/register", {
          name,
          email: `${name}@example.com`,
        })
      ).status,
      201,
    );
    const response = await request("/api/auth/verify", {
      token: token(),
      password,
    });
    assert.equal(response.status, 200);
    return response;
  };
  return {
    store,
    mail,
    request,
    token,
    register,
    failMail: () => {
      failMail = true;
    },
  };
}

test("production without SMTP supports accounts and MCP without issuing mail links", async (t) => {
  const keys = [
    "NODE_ENV",
    "SMTP_HOST",
    "SMTP_FROM",
    "EMAIL_VERIFICATION_REQUIRED",
  ];
  const previous = keys.map((key) => process.env[key]);
  t.after(() =>
    keys.forEach((key, i) => {
      if (previous[i] === undefined) delete process.env[key];
      else process.env[key] = previous[i];
    }),
  );
  process.env.NODE_ENV = "production";
  delete process.env.SMTP_HOST;
  delete process.env.SMTP_FROM;
  delete process.env.EMAIL_VERIFICATION_REQUIRED;
  const dir = await mkdtemp(join(tmpdir(), "assh-mail-"));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const mailer = createMailer(dir);
  assert.equal(mailer.mode, "disabled");
  const f = await fixture(t, false, mailer);
  assert.equal(
    (await f.request("/api/public-config")).body.mailMode,
    "disabled",
  );
  const data = { name: "No mail", email: "no-mail@example.com", password };
  const user = await f.request("/api/auth/register", data);
  assert.equal(user.status, 201);
  assert.equal(user.body.email_verified, false);
  assert.equal((await f.request("/api/auth/login", data)).status, 200);
  assert.equal(
    (await f.request("/api/devices", undefined, user.cookie)).status,
    200,
  );
  const token = await f.request(
    "/api/tokens",
    { name: "no-mail", scope: "read" },
    user.cookie,
  );
  assert.equal(token.status, 201);
  const tools = await f.request(
    "/mcp",
    { jsonrpc: "2.0", id: 1, method: "tools/list" },
    "",
    "POST",
    {
      Authorization: `Bearer ${token.body.token}`,
      Accept: "application/json, text/event-stream",
    },
  );
  assert.equal(tools.body.result.tools.length, 6);
  const team = await f.request("/api/teams", { name: "No mail" }, user.cookie);
  assert.equal(
    (
      await f.request(
        `/api/teams/${team.body.id}/invitations`,
        { email: "recipient@example.com" },
        user.cookie,
      )
    ).status,
    503,
  );
  assert.deepEqual(f.store.all("SELECT * FROM invitations"), []);
  const known = await f.request("/api/auth/forgot-password", {
    email: data.email,
  });
  const unknown = await f.request("/api/auth/forgot-password", {
    email: "unknown@example.com",
  });
  assert.equal(known.status, 200);
  assert.deepEqual(known, unknown);
  assert.deepEqual(f.store.all("SELECT * FROM email_tokens"), []);
  assert.deepEqual(await readdir(dir), []);

  process.env.EMAIL_VERIFICATION_REQUIRED = "true";
  assert.throws(
    () => createMailer(dir),
    /EMAIL_VERIFICATION_REQUIRED=true requires SMTP/,
  );
  process.env.SMTP_HOST = "smtp.example.com";
  assert.throws(() => createMailer(dir), /SMTP_FROM is required/);
  process.env.SMTP_FROM = "sender@example.com";
  assert.equal(createMailer(dir).mode, "smtp");
});

test("verification defaults off; toggling it enforces Web/MCP access without changing identity", async (t) => {
  const f = await fixture(t, false);
  assert.equal(
    (await f.request("/api/public-config")).body.emailVerificationRequired,
    false,
  );
  const data = { name: "Immediate", email: "immediate@example.com", password };
  assert.equal(
    (await f.request("/api/auth/register", { ...data, password: "short" }))
      .status,
    400,
  );
  const user = await f.request("/api/auth/register", data);
  assert.equal(user.status, 201);
  assert.ok(user.cookie);
  assert.equal(
    user.body.email_verified,
    false,
    "bypassing the gate must not attest mailbox ownership",
  );
  assert.equal(f.mail.length, 0);
  assert.equal(
    (
      await f.request("/api/auth/register", {
        ...data,
        password: "Do-not-replace-password",
      })
    ).status,
    409,
  );
  assert.equal((await f.request("/api/auth/login", data)).status, 200);
  assert.equal(
    (await f.request("/api/devices", undefined, user.cookie)).status,
    200,
  );
  const minted = await f.request(
    "/api/tokens",
    { name: "immediate", scope: "read" },
    user.cookie,
  );
  assert.equal(minted.status, 201);
  const listTools = () =>
    f.request(
      "/mcp",
      { jsonrpc: "2.0", id: 1, method: "tools/list" },
      "",
      "POST",
      {
        Authorization: `Bearer ${minted.body.token}`,
        Accept: "application/json, text/event-stream",
      },
    );
  assert.equal((await listTools()).body.result.tools.length, 6);

  process.env.EMAIL_VERIFICATION_REQUIRED = "true";
  assert.equal(
    (await f.request("/api/public-config")).body.emailVerificationRequired,
    true,
  );
  assert.equal(
    (await f.request("/api/devices", undefined, user.cookie)).status,
    403,
  );
  assert.equal((await listTools()).status, 403);
  process.env.EMAIL_VERIFICATION_REQUIRED = "false";
  assert.equal(
    (await f.request("/api/devices", undefined, user.cookie)).status,
    200,
  );
  assert.equal((await listTools()).status, 200);
  assert.equal(
    (await f.request("/api/me", undefined, user.cookie)).body.email_verified,
    false,
  );

  const team = await f.request(
    "/api/teams",
    { name: "No verification" },
    user.cookie,
  );
  const recipient = await f.request("/api/auth/register", {
    ...data,
    email: "recipient@example.com",
  });
  await f.request(
    `/api/teams/${team.body.id}/invitations`,
    { email: recipient.body.email },
    user.cookie,
  );
  const token = f.token();
  assert.equal(
    (await f.request("/api/invitations/accept", { token }, user.cookie)).status,
    403,
  );
  assert.equal(
    (await f.request("/api/invitations/accept", { token }, recipient.cookie))
      .status,
    200,
  );
  await f.request("/api/auth/forgot-password", { email: data.email });
  assert.equal(
    (
      await f.request("/api/auth/reset", {
        token: f.token(),
        password: "Recovered-password-07",
      })
    ).status,
    200,
  );
  assert.equal((await listTools()).status, 401);
  assert.equal(
    (
      await f.request("/api/auth/login", {
        email: data.email,
        password: "Recovered-password-07",
      })
    ).status,
    200,
  );
});

test("mailbox verification is one-use, purpose-bound and required for web and MCP", async (t) => {
  const f = await fixture(t);
  const started = await f.request("/api/auth/register", {
    name: "Claim",
    email: "claim@example.com",
    password: "Attacker-chosen-password",
  });
  assert.equal(started.cookie, "");
  assert.equal(started.status, 201);
  const token = f.token();
  assert.ok(!JSON.stringify(started).includes(token));
  assert.ok(
    !JSON.stringify(f.store.all("SELECT * FROM email_tokens")).includes(token),
  );
  assert.equal(
    (
      await f.request("/api/auth/login", {
        email: "claim@example.com",
        password: "Attacker-chosen-password",
      })
    ).status,
    401,
  );
  assert.equal(
    (await f.request("/api/auth/reset", { token, password })).status,
    400,
  );
  assert.equal(
    (await f.request("/api/auth/verification", { email: "claim@example.com" }))
      .status,
    200,
  );
  assert.equal(f.mail.length, 1, "resend is throttled per mailbox");
  const verified = await f.request("/api/auth/verify", { token, password });
  assert.equal(verified.body.email_verified, true);
  assert.equal(
    (await f.request("/api/auth/verify", { token, password })).status,
    400,
  );
  assert.equal(
    (await f.request("/api/devices", undefined, verified.cookie)).status,
    200,
  );

  // Legacy accounts keep their data but cannot use unverified sessions/tokens.
  f.store.run(
    "INSERT INTO users(id,name,email,password) VALUES('legacy','Legacy','legacy@example.com',?)",
    await passwordHash(password),
  );
  const legacy = await f.request("/api/auth/login", {
    email: "legacy@example.com",
    password,
  });
  assert.equal(legacy.body.email_verified, false);
  const legacyToken = randomBytes(32).toString("base64url");
  f.store.run(
    "INSERT INTO tokens(id,user_id,name,hash,prefix,scope,expires_at,created_at) VALUES('legacy-token','legacy','old',?,'old','read','2100-01-01T00:00:00.000Z','now')",
    hash(legacyToken),
  );
  assert.equal(
    (
      await f.request("/mcp", {}, "", "POST", {
        Authorization: `Bearer ${legacyToken}`,
      })
    ).status,
    403,
  );
  assert.equal(
    (await f.request("/api/devices", undefined, legacy.cookie)).status,
    403,
  );
  assert.equal(
    (
      await f.request(
        "/api/tokens",
        { name: "forbidden", scope: "execute" },
        legacy.cookie,
      )
    ).status,
    403,
  );
  await f.request("/api/auth/verification", { email: "legacy@example.com" });
  const expired = f.token();
  f.store.run(
    "UPDATE email_tokens SET expires_at='2000-01-01T00:00:00.000Z' WHERE hash=?",
    hash(expired),
  );
  assert.equal(
    (await f.request("/api/auth/verify", { token: expired, password })).status,
    400,
  );
  assert.equal(
    (await f.request("/api/auth/logout", {}, legacy.cookie)).status,
    200,
  );
});

test("password recovery rejects replay/races and revokes all sessions, tokens and older links", async (t) => {
  const f = await fixture(t);
  const user = await f.register("recover");
  const second = await f.request("/api/auth/login", {
    email: user.body.email,
    password,
  });
  const mcp = await f.request(
    "/api/tokens",
    { name: "client", scope: "execute" },
    user.cookie,
  );
  const known = await f.request("/api/auth/forgot-password", {
    email: user.body.email,
  });
  const first = f.token();
  const unknown = await f.request("/api/auth/forgot-password", {
    email: "absent@example.com",
  });
  assert.deepEqual(known, unknown);
  f.store.run("UPDATE email_tokens SET created_at='2000-01-01T00:00:00.000Z'");
  await f.request("/api/auth/forgot-password", { email: user.body.email });
  const latest = f.token();
  assert.notEqual(first, latest);
  assert.equal(
    (await f.request("/api/auth/reset", { token: first, password })).status,
    400,
  );
  const nextPassword = "New-mailbox-password-83";
  const race = await Promise.all(
    [1, 2].map(() =>
      f.request("/api/auth/reset", { token: latest, password: nextPassword }),
    ),
  );
  assert.deepEqual(race.map((r) => r.status).sort(), [200, 400]);
  for (const cookie of [user.cookie, second.cookie])
    assert.equal((await f.request("/api/me", undefined, cookie)).status, 401);
  assert.ok(
    f.store.get<{ revoked_at: string }>(
      "SELECT revoked_at FROM tokens WHERE id=?",
      mcp.body.id,
    )?.revoked_at,
  );
  assert.equal(
    (
      await f.request("/mcp", {}, "", "POST", {
        Authorization: `Bearer ${mcp.body.token}`,
      })
    ).status,
    401,
  );
  assert.equal(
    (await f.request("/api/auth/login", { email: user.body.email, password }))
      .status,
    401,
  );
  const login = await f.request("/api/auth/login", {
    email: user.body.email,
    password: nextPassword,
  });
  assert.equal(login.status, 200);
  await f.request("/api/auth/forgot-password", { email: user.body.email });
  const superseded = f.token();
  assert.equal(
    (
      await f.request(
        "/api/auth/password",
        { current: nextPassword, password },
        login.cookie,
      )
    ).status,
    200,
  );
  assert.equal(
    (
      await f.request("/api/auth/reset", {
        token: superseded,
        password: nextPassword,
      })
    ).status,
    400,
  );
});

test("invitations require recipient consent and current inviter authority, with no direct-add bypass", async (t) => {
  const f = await fixture(t);
  const owner = await f.register("owner"),
    member = await f.register("member"),
    other = await f.register("other");
  const team = await f.request(
    "/api/teams",
    { name: "Platform" },
    owner.cookie,
  );
  const path = `/api/teams/${team.body.id}`;
  const invite = async (
    email: string,
    role = "member",
    cookie = owner.cookie,
  ) => f.request(`${path}/invitations`, { email, role }, cookie);
  const issued = await invite(member.body.email);
  assert.equal(issued.status, 201);
  const token = f.token();
  assert.equal(
    (await f.request(`${path}/members`, undefined, owner.cookie)).body.length,
    1,
  );
  assert.equal(
    (
      await f.request(
        `${path}/members`,
        { email: member.body.email },
        owner.cookie,
      )
    ).status,
    404,
  );
  assert.equal(
    (await f.request("/api/invitations/accept", { token }, other.cookie))
      .status,
    403,
  );
  const inspect = await f.request(
    "/api/invitations/inspect",
    { token },
    member.cookie,
  );
  assert.equal(inspect.body.team_name, "Platform");
  assert.equal(
    (await f.request(`${path}/members`, undefined, owner.cookie)).body.length,
    1,
  );
  assert.ok(
    !JSON.stringify(
      (await f.request(`${path}/invitations`, undefined, owner.cookie)).body,
    ).includes(token),
  );
  assert.equal(
    (await f.request("/api/invitations/accept", { token }, member.cookie))
      .status,
    200,
  );
  assert.equal(
    (await f.request("/api/invitations/accept", { token }, member.cookie))
      .status,
    400,
  );
  assert.equal(
    (await invite(other.body.email, "admin", member.cookie)).status,
    403,
  );

  await invite(other.body.email, "admin");
  assert.equal(
    (
      await f.request(
        "/api/invitations/accept",
        { token: f.token() },
        other.cookie,
      )
    ).status,
    200,
  );
  assert.equal(
    (await invite("unregistered@example.com", "admin", other.cookie)).status,
    403,
  );
  const pending = await invite(
    "unregistered@example.com",
    "member",
    other.cookie,
  );
  assert.equal(pending.status, 201, "recipient need not exist when invited");
  const pendingToken = f.token();
  const recipient = await f.register("unregistered");
  await f.request(
    `${path}/members/${other.body.id}`,
    undefined,
    owner.cookie,
    "DELETE",
  );
  assert.equal(
    (
      await f.request(
        "/api/invitations/accept",
        { token: pendingToken },
        recipient.cookie,
      )
    ).status,
    400,
  );

  const revocable = await invite(recipient.body.email);
  const revoked = f.token();
  assert.equal(
    (
      await f.request(
        `${path}/invitations/${revocable.body.id}`,
        undefined,
        owner.cookie,
        "DELETE",
      )
    ).status,
    200,
  );
  assert.equal(
    (
      await f.request(
        "/api/invitations/accept",
        { token: revoked },
        recipient.cookie,
      )
    ).status,
    400,
  );
  await invite(recipient.body.email);
  const expired = f.token();
  f.store.run("UPDATE invitations SET expires_at='2000-01-01T00:00:00.000Z'");
  assert.equal(
    (
      await f.request(
        "/api/invitations/accept",
        { token: expired },
        recipient.cookie,
      )
    ).status,
    400,
  );
});

test("failed delivery cannot leave a usable invitation or verification token", async (t) => {
  const f = await fixture(t);
  const owner = await f.register("owner");
  const team = await f.request("/api/teams", { name: "No mail" }, owner.cookie);
  f.failMail();
  const failed = await f.request(
    `/api/teams/${team.body.id}/invitations`,
    { email: "member@example.com" },
    owner.cookie,
  );
  assert.equal(failed.status, 503);
  assert.ok(!JSON.stringify(failed).includes("sensitive"));
  assert.deepEqual(f.store.all("SELECT * FROM invitations"), []);
  const requested = await f.request("/api/auth/register", {
    name: "Mail",
    email: "mail@example.com",
  });
  assert.equal(
    requested.status,
    201,
    "public responses must not reveal account existence or transport details",
  );
  assert.deepEqual(f.store.all("SELECT * FROM email_tokens"), []);
});
