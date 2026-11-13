import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import type { Express } from "express";
import { z } from "zod";
import type { Store, Device, Token } from "./store.js";
import {
  type Actor,
  HttpError,
  access,
  assertActive,
  hash,
  now,
  publicDevice,
} from "./security.js";
import { SSHService, type Operation } from "./ssh.js";

export function mountMcp(app: Express, store: Store, ssh: SSHService) {
  app.all("/mcp", async (req, res) => {
    const bearer = req.headers.authorization?.match(/^Bearer (.+)$/i)?.[1];
    const token =
      bearer &&
      store.get<Token>(
        "SELECT * FROM tokens WHERE hash=? AND revoked_at IS NULL AND expires_at>?",
        hash(bearer),
        now(),
      );
    if (!token) {
      res.setHeader("WWW-Authenticate", 'Bearer realm="AsshManager"');
      res.status(401).json({ error: "需要有效的 MCP Bearer 令牌" });
      return;
    }
    assertActive(store, { id: token.user_id, source: "mcp", token });
    if (req.method !== "POST") {
      res.setHeader("Allow", "POST");
      res.status(405).end();
      return;
    }
    store.run("UPDATE tokens SET last_used_at=? WHERE id=?", now(), token.id);
    const actor: Actor = { id: token.user_id, source: "mcp", token };
    const server = new McpServer({ name: "assh-manager", version: "0.1.0" });
    const text = (value: unknown) => ({
      content: [{ type: "text" as const, text: JSON.stringify(value) }],
    });
    const run = async (id: string, op: Operation) => {
      try {
        return text(await ssh.run(actor, id, op));
      } catch (error) {
        return {
          isError: true,
          ...text({
            error: error instanceof HttpError ? error.message : "SSH 操作失败",
          }),
        };
      }
    };
    const server_id = z
      .string()
      .uuid()
      .describe("Device ID returned by ssh_list_servers");
    server.registerTool(
      "ssh_list_servers",
      {
        description:
          "List only SSH devices this token owner can access. View permission grants metadata and ping, not shell or file access.",
        annotations: { readOnlyHint: true, openWorldHint: false },
        inputSchema: {},
      },
      async () => {
        assertActive(store, actor);
        return text(
          store
            .all<Device>("SELECT * FROM devices ORDER BY name")
            .filter((d) => access(store, d, actor.id))
            .map((d) => publicDevice(store, d, actor.id)),
        );
      },
    );
    server.registerTool(
      "ssh_ping",
      {
        description:
          "Test an authenticated SSH connection with mandatory pinned host-key verification.",
        inputSchema: { server_id },
        annotations: { readOnlyHint: true, openWorldHint: true },
      },
      async ({ server_id }) => run(server_id, { operation: "ping" }),
    );
    server.registerTool(
      "ssh_execute",
      {
        description:
          "Execute an arbitrary shell command. Requires execute permission AND an execute-scoped token. May change or destroy remote data. No sudo escalation is provided. Max 60 seconds / 256 KiB output. Closing the connection does not guarantee remote process termination.",
        inputSchema: {
          server_id,
          command: z.string().min(1).max(8192),
          timeout: z.number().int().min(1).max(60).default(30),
        },
        annotations: {
          readOnlyHint: false,
          destructiveHint: true,
          openWorldHint: true,
        },
      },
      async ({ server_id, ...args }) =>
        run(server_id, { operation: "execute", ...args }),
    );
    for (const operation of ["list_directory", "read_file"] as const) {
      server.registerTool(
        `ssh_${operation}`,
        {
          description: `${operation === "read_file" ? "Read a UTF-8 text file (max 256 KiB)" : "List a directory (max 1000 entries)"} over SFTP. Requires execute permission and execute token; metadata-only viewers cannot read files.`,
          inputSchema: {
            server_id,
            path: z.string().min(1).max(4096).startsWith("/"),
          },
          annotations: { readOnlyHint: true, openWorldHint: true },
        },
        async ({ server_id, path }) => run(server_id, { operation, path }),
      );
    }
    server.registerTool(
      "ssh_write_file",
      {
        description:
          "Write a UTF-8 file over SFTP (max 64 KiB). Requires execute permission/token. Creates new files only unless overwrite=true; overwriting is destructive and non-atomic.",
        inputSchema: {
          server_id,
          path: z.string().min(1).max(4096).startsWith("/"),
          content: z.string().max(65536),
          overwrite: z.boolean().default(false),
        },
        annotations: {
          readOnlyHint: false,
          destructiveHint: true,
          openWorldHint: true,
        },
      },
      async ({ server_id, ...args }) =>
        run(server_id, { operation: "write_file", ...args }),
    );
    const transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: undefined,
      enableJsonResponse: true,
    });
    res.on("close", () => {
      void transport.close();
      void server.close();
    });
    await server.connect(transport);
    await transport.handleRequest(req, res, req.body);
  });
}
