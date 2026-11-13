import { test } from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { Store, type Device } from "../server/store.js";
import { encrypt, decrypt } from "../server/security.js";
import { resolveTarget } from "../server/ssh.js";

test("authenticated encryption binds credentials to the device and rejects tampering", () => {
  const key = randomBytes(32);
  const value = { password: "a-test-secret" };
  const encrypted = encrypt(key, "device-a", value);
  assert.deepEqual(decrypt(key, "device-a", encrypted), value);
  assert.notEqual(encrypt(key, "device-a", value), encrypted);
  assert.throws(() => decrypt(key, "device-b", encrypted));
  assert.throws(() => decrypt(randomBytes(32), "device-a", encrypted));
  const parts = encrypted.split(".");
  const body = Buffer.from(parts[2], "base64");
  body[0] ^= 1;
  parts[2] = body.toString("base64");
  assert.throws(() => decrypt(key, "device-a", parts.join(".")));
});

test("network boundary handles IPv4, IPv6 and mapped addresses without bypasses", async () => {
  for (const host of [
    "127.0.0.1",
    "10.0.0.7",
    "192.168.1.1",
    "::1",
    "::ffff:127.0.0.1",
    "169.254.169.254",
    "100.100.100.200",
    "fc00::1",
  ])
    await assert.rejects(() => resolveTarget(host, []));
  assert.equal(await resolveTarget("127.0.0.1", ["127.0.0.1/32"]), "127.0.0.1");
  await assert.rejects(() => resolveTarget("169.254.169.254", ["0.0.0.0/0"]));
  await assert.rejects(() => resolveTarget("100.100.100.200", ["0.0.0.0/0"]));
  await assert.rejects(() => resolveTarget("fd00:ec2::254", ["fc00::/7"]));
  await assert.rejects(() =>
    resolveTarget("::ffff:100.100.100.200", ["0.0.0.0/0"]),
  );
  assert.equal(await resolveTarget("8.8.8.8", []), "8.8.8.8");
});

test("SQLite upgrades legacy accounts/devices without losing credentials and rolls back atomically", () => {
  const dir = mkdtempSync(join(tmpdir(), "assh-db-"));
  try {
    let store = new Store(join(dir, "test.db"));
    store.run(
      "INSERT INTO users(id,name,email,password) VALUES('a','A','a@example.com','hashed')",
    );
    const key = randomBytes(32);
    const encrypted = encrypt(key, "d", { password: "keep-this-credential" });
    store.run(
      "INSERT INTO devices(id,owner_id,name,host,port,username,note,fingerprint,credential,auth_type,created_at) VALUES('d','a','Device','host',22,'deploy','','fingerprint',?,'password','now')",
      encrypted,
    );
    store.db.exec(
      "ALTER TABLE devices ADD COLUMN environment TEXT NOT NULL DEFAULT 'production'; ALTER TABLE users DROP COLUMN email_verified_at; PRAGMA user_version=1;",
    );
    assert.throws(() =>
      store.transaction(() => {
        store.run(
          "INSERT INTO teams(id,name,created_at) VALUES('t','T','now')",
        );
        throw new Error("abort");
      }),
    );
    assert.deepEqual(store.all("SELECT * FROM teams"), []);
    store.db.close();
    store = new Store(join(dir, "test.db"));
    const device = store.get<Device>("SELECT * FROM devices WHERE id='d'")!;
    assert.ok(!("environment" in device));
    assert.equal(device.host, "host");
    assert.deepEqual(decrypt(key, "d", device.credential), {
      password: "keep-this-credential",
    });
    assert.equal(
      store.get<{ email_verified_at: string | null }>(
        "SELECT email_verified_at FROM users WHERE id='a'",
      )!.email_verified_at,
      null,
    );
    assert.equal(
      store.get<{ name: string }>("SELECT name FROM users WHERE id='a'")!.name,
      "A",
    );
    store.db.close();
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
