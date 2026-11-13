import nodemailer from "nodemailer";
import { mkdir, writeFile } from "node:fs/promises";
import { randomUUID } from "node:crypto";
import { join } from "node:path";

export interface Mail {
  to: string;
  subject: string;
  text: string;
}
export interface Mailer {
  mode: "smtp" | "local";
  send(mail: Mail): Promise<void>;
}

export function createMailer(dataDir: string): Mailer {
  if (!process.env.SMTP_HOST) {
    if (process.env.NODE_ENV === "production")
      throw new Error("Production requires SMTP_HOST and SMTP_FROM");
    const directory = join(dataDir, "mail");
    return {
      mode: "local",
      async send(mail) {
        await mkdir(directory, { recursive: true, mode: 0o700 });
        await writeFile(
          join(directory, `${Date.now()}-${randomUUID()}.json`),
          JSON.stringify(mail),
          { mode: 0o600, flag: "wx" },
        );
      },
    };
  }
  const from = process.env.SMTP_FROM;
  if (!from) throw new Error("SMTP_FROM is required");
  const port = Number(process.env.SMTP_PORT ?? 587);
  if (!Number.isInteger(port) || port < 1 || port > 65535)
    throw new Error("Invalid SMTP_PORT");
  const transport = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port,
    secure: port === 465,
    requireTLS: port !== 465,
    auth: process.env.SMTP_USER
      ? {
          user: process.env.SMTP_USER,
          pass: process.env.SMTP_PASSWORD,
        }
      : undefined,
    connectionTimeout: 10000,
    greetingTimeout: 10000,
    socketTimeout: 20000,
    disableFileAccess: true,
    disableUrlAccess: true,
  });
  return {
    mode: "smtp",
    async send(mail) {
      await transport.sendMail({ from, ...mail });
    },
  };
}
