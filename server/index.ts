import { resolve, join } from "node:path";
import { createApp } from "./app.js";
import { Store } from "./store.js";
import { loadKey } from "./security.js";
import { createMailer } from "./mail.js";

const port = Number(process.env.PORT ?? 3000);
const dataDir = resolve(process.env.DATA_DIR ?? "data");
if (
  process.env.NODE_ENV === "production" &&
  !process.env.PUBLIC_URL?.startsWith("https://")
)
  throw new Error("Production requires an HTTPS PUBLIC_URL");
const key = loadKey(dataDir);
const store = new Store(join(dataDir, "assh.sqlite"));
const app = createApp({
  store,
  key,
  publicUrl: process.env.PUBLIC_URL ?? `http://localhost:${port}`,
  mailer: createMailer(dataDir),
  allowedCidrs: (process.env.SSH_ALLOWED_CIDRS ?? "")
    .split(",")
    .filter(Boolean),
  trustProxy: process.env.TRUST_PROXY === "1",
});
const server = app.listen(port, "0.0.0.0", () =>
  console.log(`AsshManager ready on port ${port}`),
);
server.requestTimeout = 90000;
process.on("SIGTERM", () => {
  server.close(() => {
    store.db.close();
    process.exit(0);
  });
});
