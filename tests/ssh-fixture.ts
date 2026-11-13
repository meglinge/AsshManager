import { execFileSync, spawn } from "node:child_process";
import {
  mkdtempSync,
  readFileSync,
  writeFileSync,
  rmSync,
  existsSync,
} from "node:fs";
import { tmpdir, userInfo } from "node:os";
import { join } from "node:path";
import { createServer, connect } from "node:net";
import { once } from "node:events";

// A real, unprivileged OpenSSH daemon. Only disposable generated keys are accepted.
export async function sshFixture() {
  const sshd = process.env.SSHD_PATH ?? "/usr/sbin/sshd";
  if (!existsSync(sshd))
    throw new Error("Install openssh-server to run the SSH integration tests");
  const dir = mkdtempSync(join(tmpdir(), "assh-ssh-"));
  const listener = createServer().listen(0, "127.0.0.1");
  await once(listener, "listening");
  const port = (listener.address() as { port: number }).port;
  await new Promise<void>((resolve) => listener.close(() => resolve()));
  for (const name of ["host", "client"])
    execFileSync("ssh-keygen", [
      "-q",
      "-t",
      "ed25519",
      "-N",
      "",
      "-f",
      join(dir, name),
    ]);
  writeFileSync(
    join(dir, "authorized_keys"),
    readFileSync(join(dir, "client.pub")),
    { mode: 0o600 },
  );
  writeFileSync(
    join(dir, "sshd_config"),
    `
ListenAddress 127.0.0.1
Port ${port}
HostKey ${join(dir, "host")}
PidFile ${join(dir, "sshd.pid")}
AuthorizedKeysFile ${join(dir, "authorized_keys")}
StrictModes no
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
UsePAM no
AllowUsers ${userInfo().username}
Subsystem sftp internal-sftp
LogLevel ERROR
`,
  );
  const child = spawn(sshd, ["-D", "-e", "-f", join(dir, "sshd_config")], {
    stdio: ["ignore", "ignore", "pipe"],
  });
  let errors = "";
  child.stderr.on("data", (data) => (errors += data.toString()));
  const stop = async () => {
    if (child.exitCode === null) {
      child.kill("SIGTERM");
      await once(child, "exit");
    }
    rmSync(dir, { recursive: true, force: true });
  };
  try {
    for (let tries = 0; ; tries++) {
      if (child.exitCode !== null || tries > 50)
        throw new Error(`OpenSSH fixture failed: ${errors}`);
      const ready = await new Promise<boolean>((resolve) => {
        const socket = connect(port, "127.0.0.1");
        socket.once("connect", () => {
          socket.destroy();
          resolve(true);
        });
        socket.once("error", () => resolve(false));
      });
      if (ready) break;
      await new Promise((resolve) => setTimeout(resolve, 50));
    }
  } catch (error) {
    await stop();
    throw error;
  }
  return {
    dir,
    port,
    username: userInfo().username,
    privateKey: readFileSync(join(dir, "client"), "utf8"),
    fingerprint: execFileSync(
      "ssh-keygen",
      ["-lf", join(dir, "host.pub"), "-E", "sha256"],
      { encoding: "utf8" },
    ).split(" ")[1],
    stop,
  };
}
