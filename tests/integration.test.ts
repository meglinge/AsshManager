import { test } from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { once } from "node:events";
import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { createApp } from "../server/app.js";
import { Store } from "../server/store.js";
import { sshFixture } from "./ssh-fixture.js";
import type { Mail } from "../server/mail.js";

test(
  "real HTTP + SQLite + OpenSSH + MCP isolation and revocation",
  { timeout: 90000 },
  async (t) => {
    delete process.env.EMAIL_VERIFICATION_REQUIRED;
    const ssh = await sshFixture();
    t.after(ssh.stop);
    const store = new Store(":memory:");
    t.after(() => store.db.close());
    const origin = "http://localhost";
    const mail: Mail[] = [];
    const app = createApp({
      store,
      key: randomBytes(32),
      publicUrl: origin,
      mailer: {
        mode: "smtp",
        async send(message) {
          mail.push(message);
        },
      },
      allowedCidrs: ["127.0.0.1/32"],
      serveStatic: false,
    });
    const server = app.listen(0, "127.0.0.1");
    await once(server, "listening");
    t.after(
      () => new Promise<void>((resolve) => server.close(() => resolve())),
    );
    const base = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
    type Result = {
      status: number;
      body: any;
      cookie: string;
      headers: Headers;
    };
    const request = async (
      path: string,
      method = "GET",
      body?: unknown,
      cookie = "",
      headers: Record<string, string> = {},
    ): Promise<Result> => {
      const response = await fetch(`${base}${path}`, {
        method,
        headers: {
          origin,
          "Content-Type": "application/json",
          cookie,
          ...headers,
        },
        body: body === undefined ? undefined : JSON.stringify(body),
      });
      const text = await response.text();
      return {
        status: response.status,
        body: text ? JSON.parse(text) : null,
        cookie: response.headers.get("set-cookie")?.split(";")[0] ?? "",
        headers: response.headers,
      };
    };
    const emailToken = () =>
      new URLSearchParams(
        new URL(mail.at(-1)!.text.match(/http:\/\/\S+/)![0]).hash.slice(1),
      ).get("token");
    const register = async (name: string) => {
      const result = await request("/api/auth/register", "POST", {
        name,
        email: `${name}@example.com`,
        password: "Fixture-password-01",
      });
      assert.equal(result.status, 201);
      assert.equal(result.body.email_verified, false);
      return result;
    };
    const owner = await register("owner"),
      member = await register("member"),
      outsider = await register("outsider");
    assert.equal(owner.status, 201);
    const asOwner = (path: string, method = "GET", body?: unknown) =>
      request(path, method, body, owner.cookie);
    const asMember = (path: string, method = "GET", body?: unknown) =>
      request(path, method, body, member.cookie);
    const team = (await asOwner("/api/teams", "POST", { name: "Platform" }))
      .body;
    const data = {
      name: "real-ssh",
      team_id: team.id,
      host: "127.0.0.1",
      port: ssh.port,
      username: ssh.username,
      auth_type: "key",
      privateKey: ssh.privateKey,
      fingerprint: ssh.fingerprint,
    };
    const device = (await asOwner("/api/devices", "POST", data)).body;
    const runPath = `/api/devices/${device.id}/run`;
    const grant = (grants: unknown) =>
      asOwner(`/api/devices/${device.id}/grants`, "PUT", grants);
    const mint = async (cookie: string, scope: string) =>
      (
        await request(
          "/api/tokens",
          "POST",
          { name: `test-${scope}`, scope, days: 1 },
          cookie,
        )
      ).body;
    const clientFor = async (token: string) => {
      const client = new Client({ name: "integration", version: "1.0.0" });
      await client.connect(
        new StreamableHTTPClientTransport(new URL(`${base}/mcp`), {
          requestInit: { headers: { Authorization: `Bearer ${token}` } },
        }),
      );
      t.after(() => client.close());
      return client;
    };
    const tool = async (
      client: Client,
      name: string,
      args: Record<string, unknown> = {},
    ) => {
      const result = await client.callTool({ name, arguments: args });
      return {
        error: result.isError,
        value: JSON.parse((result.content as { text: string }[])[0].text),
      };
    };

    await t.test(
      "authentication, CSRF and credentials stay behind the API boundary",
      async () => {
        assert.match(owner.headers.get("set-cookie")!, /HttpOnly/);
        assert.match(owner.headers.get("set-cookie")!, /SameSite=Strict/);
        assert.equal((await request("/api/devices")).status, 401);
        assert.equal((await request("/mcp", "POST", {})).status, 401);
        assert.equal(
          (
            await request(
              "/api/teams",
              "POST",
              { name: "evil" },
              owner.cookie,
              { origin: "https://evil.example" },
            )
          ).status,
          403,
        );
        const noOrigin = await fetch(`${base}/api/teams`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            cookie: owner.cookie,
            Authorization: "Bearer bogus",
          },
          body: '{"name":"evil"}',
        });
        assert.equal(noOrigin.status, 403);
        assert.equal(
          (
            await request("/api/auth/login", "POST", {
              email: "owner@example.com",
              password: "bad",
            })
          ).status,
          401,
        );
        assert.equal(
          (
            await request("/api/auth/verify", "POST", {
              token: "a".repeat(43),
              password: "short",
            })
          ).status,
          400,
        );
        const safe = JSON.stringify((await asOwner("/api/devices")).body);
        assert.ok(!safe.includes("PRIVATE KEY"));
        assert.ok(!safe.includes("credential"));
        assert.ok(
          !store
            .get<{ credential: string }>(
              "SELECT credential FROM devices WHERE id=?",
              device.id,
            )!
            .credential.includes("PRIVATE KEY"),
        );
        assert.ok(
          !JSON.stringify(
            store.get("SELECT * FROM users WHERE id=?", owner.body.id),
          ).includes("Fixture-password-01"),
        );
      },
    );

    await t.test(
      "default deny, team membership and explicit view permission",
      async () => {
        assert.equal(
          (
            await asOwner(`/api/teams/${team.id}/invitations`, "POST", {
              email: "member@example.com",
            })
          ).status,
          201,
        );
        assert.equal(
          (
            await asMember("/api/invitations/accept", "POST", {
              token: emailToken(),
            })
          ).status,
          200,
        );
        assert.deepEqual((await asMember("/api/devices")).body, []);
        assert.equal(
          (await asMember(runPath, "POST", { operation: "ping" })).status,
          404,
        );
        assert.equal(
          (
            await request(
              `/api/teams/${team.id}/members`,
              "GET",
              undefined,
              outsider.cookie,
            )
          ).status,
          404,
        );
        assert.equal(
          (await grant([{ subject: outsider.body.id, level: "execute" }]))
            .status,
          400,
        );
        assert.equal(
          (await grant([{ subject: member.body.id, level: "view" }])).status,
          200,
        );
        assert.equal((await asMember("/api/devices")).body[0].access, "view");
        assert.equal(
          (await asMember(runPath, "POST", { operation: "ping" })).body
            .connected,
          true,
        );
        assert.equal(
          (
            await asMember(runPath, "POST", {
              operation: "execute",
              command: "id",
            })
          ).status,
          403,
        );
        assert.equal(
          (
            await asMember(runPath, "POST", {
              operation: "read_file",
              path: "/etc/passwd",
            })
          ).status,
          403,
        );
        assert.equal(
          (
            await asMember(`/api/devices/${device.id}/grants`, "PUT", [
              { subject: "*", level: "execute" },
            ])
          ).status,
          403,
        );
        assert.equal(
          (await asMember("/api/devices", "POST", data)).status,
          403,
        );
        assert.equal(
          (
            await asMember(`/api/teams/${team.id}/invitations`, "POST", {
              email: "outsider@example.com",
              role: "admin",
            })
          ).status,
          403,
        );
        assert.equal(
          (await asMember(`/api/audit?team=${team.id}`)).status,
          403,
        );
      },
    );

    const readToken = await mint(member.cookie, "read");
    const executeToken = await mint(member.cookie, "execute");
    const readClient = await clientFor(readToken.token),
      executeClient = await clientFor(executeToken.token);
    await t.test(
      "MCP negotiation, tool discovery and independent token/device restrictions",
      async () => {
        assert.equal((await executeClient.listTools()).tools.length, 6);
        assert.equal(
          (await tool(readClient, "ssh_list_servers")).value.length,
          1,
        );
        assert.equal(
          (
            await tool(executeClient, "ssh_execute", {
              server_id: device.id,
              command: "id",
            })
          ).error,
          true,
        );
        await grant([
          { subject: "*", level: "view" },
          { subject: member.body.id, level: "execute" },
        ]);
        assert.equal(
          (
            await tool(readClient, "ssh_execute", {
              server_id: device.id,
              command: "id",
            })
          ).error,
          true,
        );
        const result = await tool(executeClient, "ssh_execute", {
          server_id: device.id,
          command: "printf 'hello-42'; printf 'warning-7' >&2; exit 7",
        });
        assert.ok(!result.error);
        assert.deepEqual(result.value, {
          stdout: "hello-42",
          stderr: "warning-7",
          exitCode: 7,
          signal: null,
        });
        const events = (await asMember("/api/audit")).body;
        assert.ok(
          events.some(
            (event: { outcome: string; detail: string }) =>
              event.outcome === "failed" &&
              event.detail.includes("exit_code=7"),
          ),
        );
        assert.equal(
          (
            await request("/api/devices", "GET", undefined, "", {
              Authorization: `Bearer ${executeToken.token}`,
            })
          ).status,
          401,
        );
        const personal = await asOwner("/api/devices", "POST", {
          ...data,
          team_id: null,
          name: "private",
        });
        assert.equal(personal.status, 201);
        assert.equal(
          (await tool(executeClient, "ssh_list_servers")).value.length,
          1,
        );
        assert.equal(
          (
            await tool(executeClient, "ssh_ping", {
              server_id: personal.body.id,
            })
          ).error,
          true,
        );
      },
    );

    await t.test(
      "real SFTP read/write/list, no-clobber default, output and time limits",
      async () => {
        const path = join(ssh.dir, "remote-file.txt");
        const written = await tool(executeClient, "ssh_write_file", {
          server_id: device.id,
          path,
          content: "hello 世界\n",
        });
        assert.ok(!written.error);
        assert.equal(readFileSync(path, "utf8"), "hello 世界\n");
        assert.equal(
          (
            await tool(executeClient, "ssh_write_file", {
              server_id: device.id,
              path,
              content: "clobber",
            })
          ).error,
          true,
        );
        assert.equal(readFileSync(path, "utf8"), "hello 世界\n");
        const read = await tool(executeClient, "ssh_read_file", {
          server_id: device.id,
          path,
        });
        assert.equal(read.value.content, "hello 世界\n");
        const list = await tool(executeClient, "ssh_list_directory", {
          server_id: device.id,
          path: ssh.dir,
        });
        assert.ok(
          list.value.entries.some(
            (e: { name: string }) => e.name === "remote-file.txt",
          ),
        );
        assert.ok(
          !(
            await tool(executeClient, "ssh_write_file", {
              server_id: device.id,
              path,
              content: "changed",
              overwrite: true,
            })
          ).error,
        );
        assert.equal(readFileSync(path, "utf8"), "changed");
        writeFileSync(join(ssh.dir, "big"), Buffer.alloc(262145));
        assert.equal(
          (
            await asMember(runPath, "POST", {
              operation: "read_file",
              path: join(ssh.dir, "big"),
            })
          ).status,
          413,
        );
        assert.equal(
          (
            await asMember(runPath, "POST", {
              operation: "execute",
              command: "head -c 262145 /dev/zero",
            })
          ).status,
          413,
        );
        assert.equal(
          (
            await asMember(runPath, "POST", {
              operation: "execute",
              command: "sleep 3",
              timeout: 1,
            })
          ).status,
          504,
        );
      },
    );

    await t.test(
      "host key mismatch and blocked networks fail closed",
      async () => {
        const bad = (
          await asOwner("/api/devices", "POST", {
            ...data,
            name: "bad-key",
            fingerprint: `SHA256:${"A".repeat(43)}`,
          })
        ).body;
        const mismatch = await asOwner(`/api/devices/${bad.id}/run`, "POST", {
          operation: "ping",
        });
        assert.equal(mismatch.status, 502);
        assert.match(mismatch.body.error, /指纹/);
        for (const host of [
          "169.254.169.254",
          "10.1.2.3",
          "::ffff:169.254.169.254",
        ]) {
          const blocked = (
            await asOwner("/api/devices", "POST", {
              ...data,
              name: "blocked",
              host,
            })
          ).body;
          assert.equal(
            (
              await asOwner(`/api/devices/${blocked.id}/run`, "POST", {
                operation: "ping",
              })
            ).status,
            400,
          );
        }
        await asOwner(`/api/devices/${bad.id}`, "DELETE");
        assert.equal(
          (
            await asOwner(`/api/devices/${bad.id}/run`, "POST", {
              operation: "ping",
            })
          ).status,
          404,
        );
      },
    );

    await t.test(
      "permission changes and membership removal apply to existing MCP clients",
      async () => {
        await grant([{ subject: "*", level: "view" }]);
        assert.equal(
          (
            await tool(executeClient, "ssh_execute", {
              server_id: device.id,
              command: "id",
            })
          ).error,
          true,
        );
        await grant([{ subject: member.body.id, level: "execute" }]);
        const startedFile = join(ssh.dir, "running");
        const pending = tool(executeClient, "ssh_execute", {
          server_id: device.id,
          command: `printf started > '${startedFile}'; sleep 4; printf should-not-arrive`,
        });
        for (
          let attempt = 0;
          !existsSync(startedFile) && attempt < 100;
          attempt++
        )
          await new Promise((resolve) => setTimeout(resolve, 20));
        assert.equal(readFileSync(startedFile, "utf8"), "started");
        await asOwner(
          `/api/teams/${team.id}/members/${member.body.id}`,
          "DELETE",
        );
        assert.equal((await pending).error, true);
        assert.deepEqual(
          (await tool(executeClient, "ssh_list_servers")).value,
          [],
        );
        await asOwner(`/api/teams/${team.id}/invitations`, "POST", {
          email: "member@example.com",
        });
        assert.equal(
          (
            await asMember("/api/invitations/accept", "POST", {
              token: emailToken(),
            })
          ).status,
          200,
        );
        assert.deepEqual(
          (await tool(executeClient, "ssh_list_servers")).value,
          [],
        );
      },
    );

    await t.test(
      "revoked and expired tokens cannot reuse MCP connections; audit contains no secrets",
      async () => {
        await grant([{ subject: member.body.id, level: "execute" }]);
        assert.equal(
          (await asMember(`/api/tokens/${executeToken.id}`, "DELETE")).status,
          200,
        );
        await assert.rejects(() => executeClient.listTools());
        store.run(
          "UPDATE tokens SET expires_at='2000-01-01T00:00:00.000Z' WHERE id=?",
          readToken.id,
        );
        await assert.rejects(() => readClient.listTools());
        const ownerEvents = await asOwner(`/api/audit?team=${team.id}`);
        assert.ok(
          ownerEvents.body.some(
            (e: { source: string; action: string }) =>
              e.source === "mcp" && e.action === "ssh.write_file",
          ),
        );
        assert.ok(
          ownerEvents.body.some(
            (e: { action: string; target: string }) =>
              e.action === "team.member.remove" && e.target === "member",
          ),
        );
        const serialized = JSON.stringify(ownerEvents.body);
        assert.ok(!serialized.includes("hello 世界"));
        assert.ok(!serialized.includes("PRIVATE KEY"));
        assert.ok(!serialized.includes("printf"));
        assert.ok(!serialized.includes(executeToken.token));
        assert.ok(serialized.includes("command_sha256="));
        const freshToken = await mint(member.cookie, "read");
        const changed = await asMember("/api/auth/password", "POST", {
          current: "Fixture-password-01",
          password: "Another-fixture-password",
        });
        assert.equal(changed.status, 200);
        assert.equal((await asMember("/api/me")).status, 401);
        assert.equal(
          (await request("/api/me", "GET", undefined, changed.cookie)).status,
          200,
        );
        assert.equal(
          (
            await request("/mcp", "POST", {}, "", {
              Authorization: `Bearer ${freshToken.token}`,
            })
          ).status,
          401,
        );
        assert.equal(
          (
            await request("/api/auth/login", "POST", {
              email: "member@example.com",
              password: "Fixture-password-01",
            })
          ).status,
          401,
        );
      },
    );
  },
);
