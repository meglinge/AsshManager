import { useState } from "react";
import {
  ArrowRight,
  ChevronRight,
  Code2,
  Download,
  Plus,
  Users,
} from "lucide-react";
import {
  api,
  useResource,
  type User,
  type Team,
  type Member,
  type Audit,
  Modal,
  Form,
  Loading,
  Empty,
  ErrorBox,
  CopyButton,
  Status,
  Select,
  roleNames,
  actionNames,
  date,
  useConfirm,
} from "./common";
import { MailNotice } from "./accounts";

interface Invitation {
  id: string;
  email: string;
  role: string;
  expires_at: string;
}
export function TeamPage({
  teams,
  team,
  user,
  revision,
  select,
  create,
  changed,
}: {
  teams: Team[];
  team?: Team;
  user: User;
  revision: number;
  select: (id: string) => void;
  create: () => void;
  changed: (message?: string) => void;
}) {
  const {
    data: members,
    error,
    loading: membersLoading,
    retry: retryMembers,
  } = useResource<Member[]>(
    team ? `/teams/${team.id}/members` : null,
    revision,
  );
  const [add, setAdd] = useState(false);
  const [actionError, setActionError] = useState("");
  const [confirmDialog, confirm] = useConfirm();
  const admin = team?.role === "owner" || team?.role === "admin";
  const {
    data: invitations,
    error: invitationError,
    retry: retryInvitations,
  } = useResource<Invitation[]>(
    team && admin ? `/teams/${team.id}/invitations` : null,
    revision,
  );
  return (
    <>
      <div className="page-heading">
        <h1>团队</h1>
        <button className="button primary" onClick={create}>
          <Plus size={16} />
          创建团队
        </button>
      </div>
      {teams.length > 0 && (
        <div className="team-cards">
          {teams.map((t) => (
            <button
              className={`team-card ${team?.id === t.id ? "selected" : ""}`}
              key={t.id}
              onClick={() => {
                select(t.id);
                setAdd(false);
                setActionError("");
              }}
            >
              <span className="team-icon">
                <Users size={20} />
              </span>
              <span>
                <strong>{t.name}</strong>
                <small>
                  {t.member_count} 位成员 · {roleNames[t.role]}
                </small>
              </span>
              <ChevronRight size={18} />
            </button>
          ))}
        </div>
      )}
      {!team ? (
        !teams.length && (
          <div className="panel">
            <Empty title="还没有团队" />
          </div>
        )
      ) : (
        <div className="panel">
          <div className="table-heading">
            <h3>
              成员 <span className="count">{members?.length ?? "—"}</span>
            </h3>
            {admin && (
              <button className="button secondary" onClick={() => setAdd(true)}>
                <Plus size={16} />
                邀请成员
              </button>
            )}
          </div>
          <ErrorBox onRetry={error ? retryMembers : undefined}>
            {error || actionError}
          </ErrorBox>
          {membersLoading ? (
            <Loading />
          ) : !members ? null : (
            <div className="table-scroll">
              <table>
                <thead>
                  <tr>
                    <th>成员</th>
                    <th className="optional">邮箱</th>
                    <th>角色</th>
                    <th>
                      <span className="sr-only">操作</span>
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {members.map((m) => (
                    <tr key={m.id}>
                      <td>
                        <div className="member-name">
                          <span className="avatar">{m.name.slice(0, 1)}</span>
                          <strong>
                            {m.name}
                            {m.id === user.id && <small>（你）</small>}
                          </strong>
                        </div>
                      </td>
                      <td className="optional">{m.email}</td>
                      <td>
                        <span
                          className={`tag ${m.role === "owner" ? "positive" : m.role === "admin" ? "info" : "neutral"}`}
                        >
                          {roleNames[m.role]}
                        </span>
                      </td>
                      <td className="row-end">
                        {admin &&
                          m.role !== "owner" &&
                          (team.role === "owner" || m.role === "member") && (
                            <button
                              className="text-button danger-text"
                              onClick={async () => {
                                if (
                                  !(await confirm({
                                    title: `移除 ${m.name}？`,
                                    action: "移除",
                                  }))
                                )
                                  return;
                                try {
                                  await api(
                                    `/teams/${team.id}/members/${m.id}`,
                                    "DELETE",
                                  );
                                  changed("成员已移除");
                                } catch (e) {
                                  setActionError((e as Error).message);
                                }
                              }}
                            >
                              移除
                            </button>
                          )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}
      {team && admin && (invitationError || !!invitations?.length) && (
        <section className="panel">
          <div className="table-heading">
            <h3>
              待接受的邀请{" "}
              <span className="count">{invitations?.length ?? "—"}</span>
            </h3>
          </div>
          <ErrorBox onRetry={invitationError ? retryInvitations : undefined}>
            {invitationError}
          </ErrorBox>
          {!!invitations?.length && (
            <div className="table-scroll">
              <table>
                <thead>
                  <tr>
                    <th>邮箱</th>
                    <th>角色</th>
                    <th className="optional">有效期至</th>
                    <th>
                      <span className="sr-only">操作</span>
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {invitations.map((invite) => {
                    const expired = new Date(invite.expires_at) <= new Date();
                    return (
                      <tr key={invite.id} className={expired ? "inactive" : ""}>
                        <td>{invite.email}</td>
                        <td>{roleNames[invite.role]}</td>
                        <td className="muted optional">
                          {expired ? "已过期" : date(invite.expires_at)}
                        </td>
                        <td className="row-end">
                          {(team.role === "owner" ||
                            invite.role === "member") && (
                            <button
                              className="text-button danger-text"
                              onClick={async () => {
                                if (
                                  !(await confirm({
                                    title: `撤销发给 ${invite.email} 的邀请？`,
                                    action: "撤销",
                                  }))
                                )
                                  return;
                                try {
                                  await api(
                                    `/teams/${team.id}/invitations/${invite.id}`,
                                    "DELETE",
                                  );
                                  changed("邀请已撤销");
                                } catch (error) {
                                  setActionError((error as Error).message);
                                }
                              }}
                            >
                              撤销
                            </button>
                          )}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </section>
      )}
      {add && team && (
        <Modal
          title="邀请成员"
          description={team.name}
          close={() => setAdd(false)}
        >
          <Form
            label="发送邀请"
            cancel={() => setAdd(false)}
            submit={async (form) => {
              await api(
                `/teams/${team.id}/invitations`,
                "POST",
                Object.fromEntries(form),
              );
              setAdd(false);
              changed("邀请已发送");
            }}
          >
            <label>
              邮箱
              <input
                name="email"
                type="email"
                placeholder="colleague@company.com"
                required
                data-autofocus
              />
            </label>
            <div className="field">
              <span className="field-label">角色</span>
              <Select
                name="role"
                ariaLabel="角色"
                defaultValue="member"
                options={[
                  { value: "member", label: "成员" },
                  ...(team.role === "owner"
                    ? [{ value: "admin", label: "管理员" }]
                    : []),
                ]}
              />
            </div>
            <MailNotice />
          </Form>
        </Modal>
      )}
      {confirmDialog}
    </>
  );
}

interface Token {
  id: string;
  name: string;
  prefix: string;
  scope: string;
  expires_at: string;
  created_at: string;
  last_used_at: string | null;
  revoked_at: string | null;
}
const tools = {
  仅查看: ["ssh_list_servers", "ssh_ping"],
  可执行: [
    "ssh_execute",
    "ssh_list_directory",
    "ssh_read_file",
    "ssh_write_file",
  ],
};
export function TokenPage({
  revision,
  changed,
}: {
  revision: number;
  changed: (message?: string) => void;
}) {
  const {
    data: tokens,
    error,
    loading: tokensLoading,
    retry: retryTokens,
  } = useResource<Token[]>("/tokens", revision);
  const [add, setAdd] = useState(false);
  const [created, setCreated] = useState<string>();
  const [actionError, setActionError] = useState("");
  const [confirmDialog, confirm] = useConfirm();
  const endpoint = `${window.location.origin}/mcp`;
  const clientConfig = (token: string) =>
    JSON.stringify(
      {
        mcpServers: {
          "assh-manager": {
            type: "http",
            url: endpoint,
            headers: { Authorization: `Bearer ${token}` },
          },
        },
      },
      null,
      2,
    );
  const config = clientConfig("<YOUR_MCP_TOKEN>");
  return (
    <>
      <div className="page-heading">
        <h1>MCP 连接</h1>
        <button className="button primary" onClick={() => setAdd(true)}>
          <Plus size={16} />
          创建令牌
        </button>
      </div>
      <div className="mcp-setup">
        <section className="panel setup-info">
          <h3>服务地址</h3>
          <div className="endpoint">
            <code>{endpoint}</code>
            <CopyButton value={endpoint} />
          </div>
          <h3>可用工具</h3>
          <dl className="tool-groups">
            {Object.entries(tools).map(([scope, names]) => (
              <div key={scope}>
                <dt>{scope}</dt>
                <dd>
                  {names.map((name) => (
                    <code key={name}>{name}</code>
                  ))}
                </dd>
              </div>
            ))}
          </dl>
        </section>
        <section className="config-panel">
          <div>
            <span>
              <Code2 size={16} /> 客户端配置
            </span>
            <CopyButton value={config} />
          </div>
          <pre>{config}</pre>
        </section>
      </div>
      <div className="panel">
        <div className="table-heading">
          <h3>
            访问令牌 <span className="count">{tokens?.length ?? "—"}</span>
          </h3>
        </div>
        <ErrorBox onRetry={error ? retryTokens : undefined}>
          {error || actionError}
        </ErrorBox>
        {tokensLoading ? (
          <Loading />
        ) : !tokens ? null : tokens.length ? (
          <div className="table-scroll">
            <table>
              <thead>
                <tr>
                  <th>名称</th>
                  <th>权限</th>
                  <th className="optional">到期时间</th>
                  <th className="optional">最近使用</th>
                  <th>状态</th>
                  <th>
                    <span className="sr-only">操作</span>
                  </th>
                </tr>
              </thead>
              <tbody>
                {tokens.map((token) => {
                  const active =
                    !token.revoked_at &&
                    new Date(token.expires_at) > new Date();
                  return (
                    <tr key={token.id} className={active ? "" : "inactive"}>
                      <td className="wrap">
                        <strong>{token.name}</strong>
                        <small className="block mono muted optional">
                          {token.prefix}••••••••
                        </small>
                      </td>
                      <td>
                        <span className="tag neutral">
                          {token.scope === "read" ? "仅查看" : "可执行"}
                        </span>
                      </td>
                      <td className="muted optional">
                        {date(token.expires_at)}
                      </td>
                      <td className="muted optional">
                        {date(token.last_used_at)}
                      </td>
                      <td>
                        <span
                          className={`tag ${active ? "positive" : "neutral"}`}
                        >
                          {token.revoked_at
                            ? "已撤销"
                            : active
                              ? "有效"
                              : "已过期"}
                        </span>
                      </td>
                      <td className="row-end">
                        {active && (
                          <button
                            className="text-button danger-text"
                            onClick={async () => {
                              if (
                                !(await confirm({
                                  title: `撤销 ${token.name}？`,
                                  action: "撤销",
                                }))
                              )
                                return;
                              try {
                                await api(`/tokens/${token.id}`, "DELETE");
                                changed("令牌已撤销");
                              } catch (e) {
                                setActionError((e as Error).message);
                              }
                            }}
                          >
                            撤销
                          </button>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        ) : (
          <Empty title="还没有令牌" />
        )}
      </div>
      {add && (
        <Modal title="创建 MCP 令牌" close={() => setAdd(false)}>
          <Form
            label="创建令牌"
            cancel={() => setAdd(false)}
            submit={async (form) => {
              const result = await api<{ token: string }>("/tokens", "POST", {
                name: form.get("name"),
                scope: form.get("scope"),
                days: Number(form.get("days")),
              });
              setAdd(false);
              setCreated(result.token);
              changed();
            }}
          >
            <label>
              名称
              <input name="name" maxLength={80} data-autofocus required />
            </label>
            <div className="field">
              <span className="field-label">权限</span>
              <Select
                name="scope"
                ariaLabel="权限"
                defaultValue="read"
                options={[
                  { value: "read", label: "仅查看" },
                  { value: "execute", label: "可执行" },
                ]}
              />
            </div>
            <div className="field">
              <span className="field-label">有效期</span>
              <Select
                name="days"
                ariaLabel="有效期"
                defaultValue="30"
                options={[
                  { value: "7", label: "7 天" },
                  { value: "30", label: "30 天" },
                  { value: "90", label: "90 天" },
                ]}
              />
            </div>
          </Form>
        </Modal>
      )}
      {created && (
        <Modal
          title="令牌已创建"
          description="令牌只显示这一次，请立即复制。"
          close={() => setCreated(undefined)}
        >
          <div className="secret-display">
            <code>{created}</code>
            <div className="inline-actions">
              <CopyButton value={created} label="复制令牌" />
              <CopyButton
                value={clientConfig(created)}
                label="复制客户端配置"
              />
            </div>
          </div>
          <div className="form-actions">
            <button
              className="button primary"
              onClick={() => setCreated(undefined)}
            >
              我已保存
            </button>
          </div>
        </Modal>
      )}
      {confirmDialog}
    </>
  );
}

export function AuditPage({
  team,
  revision,
}: {
  team?: Team;
  revision: number;
}) {
  const [before, setBefore] = useState<number>();
  const [outcome, setOutcome] = useState("");
  const path = `/audit?${new URLSearchParams({ ...(team ? { team: team.id } : {}), ...(before ? { before: String(before) } : {}) })}`;
  const {
    data: events,
    error,
    loading: eventsLoading,
    retry: retryEvents,
  } = useResource<Audit[]>(path, revision);
  const filtered = events?.filter((e) => !outcome || e.outcome === outcome);
  const older = events?.length === 100;
  return (
    <>
      <div className="page-heading">
        <h1>审计日志</h1>
        <button
          className="button secondary"
          disabled={!events}
          onClick={() => {
            const url = URL.createObjectURL(
              new Blob([JSON.stringify(filtered, null, 2)], {
                type: "application/json",
              }),
            );
            const a = document.createElement("a");
            a.href = url;
            a.download = "assh-audit-page.json";
            a.click();
            URL.revokeObjectURL(url);
          }}
        >
          <Download size={16} />
          导出当前页
        </button>
      </div>
      <div className="panel">
        <div className="table-heading">
          <h3>{team ? "团队操作" : "我的操作"}</h3>
          <Select
            ariaLabel="按结果筛选"
            variant="compact"
            align="right"
            value={outcome}
            onChange={setOutcome}
            options={[
              { value: "", label: "全部结果" },
              { value: "success", label: "成功" },
              { value: "failed", label: "失败" },
              { value: "denied", label: "已拒绝" },
              { value: "started", label: "已开始" },
            ]}
          />
        </div>
        <ErrorBox onRetry={error ? retryEvents : undefined}>{error}</ErrorBox>
        {eventsLoading ? (
          <Loading />
        ) : !events ? null : !filtered?.length ? (
          <Empty title="暂无记录" />
        ) : (
          <div className="table-scroll">
            <table className="audit-table">
              <thead>
                <tr>
                  <th>操作</th>
                  <th>对象</th>
                  <th>操作者</th>
                  <th>来源</th>
                  <th>结果</th>
                  <th>时间</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((e) => (
                  <tr key={e.id}>
                    <td>
                      <strong title={e.action}>
                        {actionNames[e.action] ?? e.action}
                      </strong>
                    </td>
                    <td className="truncate" title={e.target}>
                      {e.target}
                    </td>
                    <td>{e.actor_name}</td>
                    <td>
                      <span
                        className={`tag ${e.source === "mcp" ? "info" : "neutral"}`}
                      >
                        {e.source === "mcp" ? "MCP" : "网页"}
                      </span>
                    </td>
                    <td>
                      <Status value={e.outcome} outcome />
                    </td>
                    <td className="muted">{date(e.created_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        {(before || older) && (
          <div className="table-footer">
            <div className="inline-actions">
              {before && (
                <button
                  className="text-button"
                  onClick={() => setBefore(undefined)}
                >
                  最新记录
                </button>
              )}
              {older && (
                <button
                  className="text-button"
                  onClick={() => setBefore(events[events.length - 1].id)}
                >
                  更早记录 <ArrowRight size={14} />
                </button>
              )}
            </div>
          </div>
        )}
      </div>
    </>
  );
}

export function SettingsPage({
  user,
  changed,
}: {
  user: User;
  changed: (message?: string) => void;
}) {
  const [revision, setRevision] = useState(0);
  return (
    <>
      <div className="page-heading">
        <h1>账号设置</h1>
      </div>
      <section className="panel padding settings-panel">
        <div className="profile-large">
          <span className="avatar">{user.name.slice(0, 1)}</span>
          <div>
            <strong>{user.name}</strong>
            <p>{user.email}</p>
          </div>
          {user.email_verified && (
            <span className="tag positive">邮箱已验证</span>
          )}
        </div>
        <h3>修改密码</h3>
        <p className="field-help">修改后，其他会话和全部 MCP 令牌将失效。</p>
        <Form
          key={revision}
          label="更新密码"
          submit={async (form) => {
            if (form.get("password") !== form.get("confirm"))
              throw new Error("两次新密码不一致");
            await api("/auth/password", "POST", {
              current: form.get("current"),
              password: form.get("password"),
            });
            setRevision((v) => v + 1);
            changed("密码已更新");
          }}
        >
          <label>
            当前密码
            <input
              name="current"
              type="password"
              autoComplete="current-password"
              required
            />
          </label>
          <label>
            新密码
            <input
              name="password"
              type="password"
              autoComplete="new-password"
              minLength={12}
              maxLength={128}
              placeholder="至少 12 位"
              required
            />
          </label>
          <label>
            确认新密码
            <input
              name="confirm"
              type="password"
              autoComplete="new-password"
              minLength={12}
              maxLength={128}
              required
            />
          </label>
        </Form>
      </section>
    </>
  );
}
export function Guide() {
  return (
    <ol className="guide">
      <li>
        <h3>选择工作空间</h3>
        <p>
          个人工作空间的服务器只有你能访问。要与同事共享，请创建团队并邀请成员。
        </p>
      </li>
      <li>
        <h3>添加服务器</h3>
        <p>
          填写连接信息和主机指纹，保存后测试连接。建议使用非 root 的专用账户。
        </p>
      </li>
      <li>
        <h3>按服务器授权</h3>
        <p>
          新服务器只有所有者和管理员能访问。在服务器的「访问权限」中为成员设置「仅查看」（查看信息、测试连接）或「可执行」（执行命令、读写文件）。
        </p>
      </li>
      <li>
        <h3>连接 AI 助手</h3>
        <p>
          在「MCP 连接」中创建令牌，把服务地址和令牌填入 AI
          客户端。令牌适用于你的所有工作空间。
        </p>
      </li>
    </ol>
  );
}
