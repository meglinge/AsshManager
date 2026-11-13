import { DatabaseSync, type SQLInputValue } from "node:sqlite";
import { mkdirSync, chmodSync } from "node:fs";
import { dirname } from "node:path";

export interface User {
  id: string;
  name: string;
  email: string;
  password: string;
  email_verified_at: string | null;
}
export interface Team {
  id: string;
  name: string;
  role: string;
}
export interface Device {
  id: string;
  owner_id: string;
  team_id: string | null;
  name: string;
  host: string;
  port: number;
  username: string;
  note: string;
  fingerprint: string;
  credential: string;
  auth_type: string;
  status: string;
  checked_at: string | null;
  created_at: string;
}
export interface Token {
  id: string;
  user_id: string;
  hash: string;
  scope: "read" | "execute";
  expires_at: string;
  revoked_at: string | null;
}

export class Store {
  db: DatabaseSync;
  constructor(path: string) {
    if (path !== ":memory:")
      mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
    this.db = new DatabaseSync(path);
    if (path !== ":memory:") chmodSync(path, 0o600);
    this.db.exec(`
      PRAGMA journal_mode=WAL;
      PRAGMA foreign_keys=ON;
      PRAGMA busy_timeout=5000;
      CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY, name TEXT NOT NULL, email TEXT NOT NULL UNIQUE,
        password TEXT NOT NULL, email_verified_at TEXT,
        created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
      );
      CREATE TABLE IF NOT EXISTS sessions (
        hash TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE, expires_at TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS teams (id TEXT PRIMARY KEY, name TEXT NOT NULL, created_at TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS members (
        team_id TEXT NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
        user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        role TEXT NOT NULL CHECK(role IN ('owner','admin','member')), PRIMARY KEY(team_id,user_id)
      );
      CREATE TABLE IF NOT EXISTS devices (
        id TEXT PRIMARY KEY, owner_id TEXT NOT NULL REFERENCES users(id),
        team_id TEXT REFERENCES teams(id) ON DELETE CASCADE,
        name TEXT NOT NULL, host TEXT NOT NULL, port INTEGER NOT NULL, username TEXT NOT NULL,
        note TEXT NOT NULL, fingerprint TEXT NOT NULL,
        credential TEXT NOT NULL, auth_type TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'unknown', checked_at TEXT, created_at TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS grants (
        device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
        subject TEXT NOT NULL, level TEXT NOT NULL CHECK(level IN ('view','execute')),
        PRIMARY KEY(device_id,subject)
      );
      CREATE TABLE IF NOT EXISTS tokens (
        id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        name TEXT NOT NULL, hash TEXT NOT NULL UNIQUE, prefix TEXT NOT NULL,
        scope TEXT NOT NULL CHECK(scope IN ('read','execute')), expires_at TEXT NOT NULL,
        created_at TEXT NOT NULL, last_used_at TEXT, revoked_at TEXT
      );
      CREATE TABLE IF NOT EXISTS audit (
        id INTEGER PRIMARY KEY AUTOINCREMENT, actor_id TEXT NOT NULL REFERENCES users(id),
        team_id TEXT, device_id TEXT, target TEXT NOT NULL, action TEXT NOT NULL,
        outcome TEXT NOT NULL, source TEXT NOT NULL, detail TEXT NOT NULL,
        created_at TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS audit_actor ON audit(actor_id,id);
      CREATE INDEX IF NOT EXISTS audit_team ON audit(team_id,id);
      CREATE INDEX IF NOT EXISTS devices_team ON devices(team_id);
      CREATE INDEX IF NOT EXISTS members_user ON members(user_id);
    `);
    this.transaction(() => {
      if (
        !this.all<{ name: string }>("PRAGMA table_info(users)").some(
          (c) => c.name === "email_verified_at",
        )
      )
        this.db.exec("ALTER TABLE users ADD COLUMN email_verified_at TEXT");
      if (
        this.all<{ name: string }>("PRAGMA table_info(devices)").some(
          (c) => c.name === "environment",
        )
      )
        this.db.exec("ALTER TABLE devices DROP COLUMN environment");
      this.db.exec(`
        CREATE TABLE IF NOT EXISTS email_tokens (
          hash TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          purpose TEXT NOT NULL CHECK(purpose IN ('verify','reset')),
          created_at TEXT NOT NULL, expires_at TEXT NOT NULL,
          UNIQUE(user_id,purpose)
        );
        CREATE TABLE IF NOT EXISTS invitations (
          id TEXT PRIMARY KEY, team_id TEXT NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
          email TEXT NOT NULL, role TEXT NOT NULL CHECK(role IN ('admin','member')),
          invited_by TEXT NOT NULL REFERENCES users(id), hash TEXT NOT NULL UNIQUE,
          created_at TEXT NOT NULL, expires_at TEXT NOT NULL,
          UNIQUE(team_id,email)
        );
        PRAGMA user_version=2;
      `);
    });
  }
  get<T>(sql: string, ...params: SQLInputValue[]) {
    return this.db.prepare(sql).get(...params) as T | undefined;
  }
  all<T>(sql: string, ...params: SQLInputValue[]) {
    return this.db.prepare(sql).all(...params) as T[];
  }
  run(sql: string, ...params: SQLInputValue[]) {
    return this.db.prepare(sql).run(...params);
  }
  transaction<T>(work: () => T): T {
    this.db.exec("BEGIN IMMEDIATE");
    try {
      const result = work();
      this.db.exec("COMMIT");
      return result;
    } catch (error) {
      this.db.exec("ROLLBACK");
      throw error;
    }
  }
}
