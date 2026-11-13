import type { Express, Response } from "express";
import { randomUUID } from "node:crypto";
import { z } from "zod";
import type { Store, User } from "./store.js";
import type { Mailer } from "./mail.js";
import {
  type Actor,
  HttpError,
  assertActive,
  audit,
  hash,
  now,
  requireTeamAdmin,
  secret,
  teamRole,
} from "./security.js";

interface Invitation {
  id: string;
  team_id: string;
  email: string;
  role: "member" | "admin";
  invited_by: string;
}

export function mountInvitations(
  app: Express,
  store: Store,
  mailer: Mailer,
  origin: string,
) {
  const actor = (res: Response) => res.locals.actor as Actor;
  const canInvite = (team: string, user: string, role: string) => {
    requireTeamAdmin(store, team, user);
    if (role === "admin" && teamRole(store, team, user) !== "owner")
      throw new HttpError(403, "仅所有者可邀请或撤销管理员邀请");
  };
  app.get("/api/teams/:id/invitations", (req, res) => {
    requireTeamAdmin(store, req.params.id, actor(res).id);
    res.json(
      store.all(
        "SELECT id,email,role,created_at,expires_at FROM invitations WHERE team_id=? ORDER BY created_at DESC",
        req.params.id,
      ),
    );
  });
  app.post("/api/teams/:id/invitations", async (req, res) => {
    const data = z
      .object({
        email: z
          .email()
          .max(254)
          .transform((v) => v.toLowerCase()),
        role: z.enum(["member", "admin"]).default("member"),
      })
      .parse(req.body);
    canInvite(req.params.id, actor(res).id, data.role);
    const old = store.get<Invitation & { created_at: string }>(
      "SELECT * FROM invitations WHERE team_id=? AND email=?",
      req.params.id,
      data.email,
    );
    if (old) {
      canInvite(req.params.id, actor(res).id, old.role);
      if (old.created_at > new Date(Date.now() - 60000).toISOString())
        throw new HttpError(429, "请等待一分钟后再发送邀请");
    }
    if (
      store.get(
        "SELECT 1 FROM members m JOIN users u ON u.id=m.user_id WHERE m.team_id=? AND u.email=?",
        req.params.id,
        data.email,
      )
    )
      throw new HttpError(409, "该邮箱已是团队成员");
    const id = randomUUID(),
      token = secret();
    const team = store.get<{ name: string }>(
      "SELECT name FROM teams WHERE id=?",
      req.params.id,
    )!;
    const expires = new Date(Date.now() + 7 * 86400000).toISOString();
    store.transaction(() => {
      store.run(
        "DELETE FROM invitations WHERE team_id=? AND email=?",
        req.params.id,
        data.email,
      );
      store.run(
        "INSERT INTO invitations(id,team_id,email,role,invited_by,hash,created_at,expires_at) VALUES(?,?,?,?,?,?,?,?)",
        id,
        req.params.id,
        data.email,
        data.role,
        actor(res).id,
        hash(token),
        now(),
        expires,
      );
    });
    try {
      await mailer.send({
        to: data.email,
        subject: "AsshManager 团队邀请",
        text: `你收到加入「${team.name}」的邀请，角色：${data.role === "admin" ? "管理员（可管理团队全部服务器和成员）" : "普通成员（按服务器授权）"}。\n\n请使用 ${data.email} 注册或登录，再打开以下链接确认加入。若站点启用了邮箱验证，请先按页面提示验证邮箱。邀请 7 天内有效；不接受则不会加入。\n\n${origin}/#${new URLSearchParams({ action: "invite", token })}\n\n如果不认识邀请人，请忽略此邮件。`,
      });
    } catch {
      store.run("DELETE FROM invitations WHERE id=?", id);
      throw new HttpError(503, "邀请邮件发送失败，请稍后重试或联系部署管理员");
    }
    assertActive(store, actor(res));
    canInvite(req.params.id, actor(res).id, data.role);
    audit(
      store,
      actor(res),
      "team.invite",
      data.email,
      "success",
      undefined,
      data.role,
      req.params.id,
    );
    res.status(201).json({ id, expires_at: expires });
  });
  app.delete("/api/teams/:id/invitations/:inviteId", (req, res) => {
    const invite = store.get<Invitation>(
      "SELECT * FROM invitations WHERE id=? AND team_id=?",
      req.params.inviteId,
      req.params.id,
    );
    requireTeamAdmin(store, req.params.id, actor(res).id);
    if (!invite) throw new HttpError(404, "邀请不存在");
    canInvite(invite.team_id, actor(res).id, invite.role);
    store.run("DELETE FROM invitations WHERE id=?", invite.id);
    audit(
      store,
      actor(res),
      "team.invite.revoke",
      invite.email,
      "success",
      undefined,
      "",
      invite.team_id,
    );
    res.json({ ok: true });
  });
  // POST inspection avoids sending the secret in a URL or consuming it on mail scanners' GETs.
  for (const action of ["inspect", "accept"] as const) {
    app.post(`/api/invitations/${action}`, (req, res) => {
      const { token } = z
        .object({ token: z.string().length(43) })
        .parse(req.body);
      const invite = store.get<Invitation>(
        "SELECT * FROM invitations WHERE hash=? AND expires_at>?",
        hash(token),
        now(),
      );
      if (!invite) throw new HttpError(400, "邀请已失效、被撤销或已接受");
      const user = store.get<User>(
        "SELECT * FROM users WHERE id=?",
        actor(res).id,
      )!;
      if (user.email !== invite.email)
        throw new HttpError(403, "请使用收到邀请的邮箱账号登录");
      canInvite(invite.team_id, invite.invited_by, invite.role);
      const team = store.get<{ name: string }>(
        "SELECT name FROM teams WHERE id=?",
        invite.team_id,
      )!;
      if (action === "inspect") {
        res.json({
          team_name: team.name,
          role: invite.role,
          email: invite.email,
        });
        return;
      }
      store.transaction(() => {
        if (teamRole(store, invite.team_id, user.id))
          throw new HttpError(409, "你已经是该团队成员");
        store.run(
          "INSERT INTO members(team_id,user_id,role) VALUES(?,?,?)",
          invite.team_id,
          user.id,
          invite.role,
        );
        store.run("DELETE FROM invitations WHERE id=?", invite.id);
        audit(
          store,
          actor(res),
          "team.member.add",
          user.name,
          "success",
          undefined,
          invite.role,
          invite.team_id,
        );
      });
      res.json({ ok: true, team_id: invite.team_id });
    });
  }
}
