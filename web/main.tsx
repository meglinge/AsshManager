import React, { useEffect, useRef, useState } from "react";
import { createRoot } from "react-dom/client";
import {
  Activity,
  ArrowRight,
  Boxes,
  ChevronRight,
  CircleAlert,
  CircleCheck,
  CircleHelp,
  LayoutDashboard,
  LogOut,
  Menu,
  Plus,
  Search,
  Server,
  Settings,
  ShieldCheck,
  Terminal,
  Users,
  X,
} from "lucide-react";
import {
  api,
  useResource,
  type User,
  type PublicConfig,
  type Team,
  type Device,
  type Audit,
  Loading,
  ErrorBox,
  Form,
  Modal,
  Empty,
  Status,
  Select,
  date,
  roleNames,
  actionNames,
} from "./common";
import { DeviceForm, DeviceDetail } from "./devices";
import { TeamPage, TokenPage, AuditPage, SettingsPage, Guide } from "./pages";
import { AccountPanel, type EmailAction } from "./accounts";
import "./style.css";

function Brand() {
  return (
    <div className="brand">
      <span className="brand-icon">
        <Terminal size={20} strokeWidth={2.5} />
      </span>
      <span>
        Assh<span className="brand-light">Manager</span>
      </span>
    </div>
  );
}
function Auth(props: {
  user: User | null;
  action: EmailAction | null;
  verificationRequired: boolean;
  finished: (user: User | null, completeAction?: boolean) => void;
  cancel: () => void;
}) {
  return (
    <main className="auth-page">
      <Brand />
      <div className="auth-card">
        <AccountPanel {...props} />
      </div>
    </main>
  );
}

type Page = "overview" | "devices" | "teams" | "tokens" | "audit" | "settings";
const navigation = [
  { id: "overview", label: "工作台", icon: LayoutDashboard },
  { id: "devices", label: "服务器", icon: Server },
  { id: "teams", label: "团队", icon: Users },
  { id: "tokens", label: "MCP 连接", icon: Boxes },
  { id: "audit", label: "审计日志", icon: Activity },
] as const;
// Each page has its own path, so a reload, a bookmark, or the back button keeps the place.
// "/mcp" is the MCP endpoint itself, so the MCP page lives at "/tokens".
const paths: Record<Page, string> = {
  overview: "/",
  devices: "/servers",
  teams: "/teams",
  tokens: "/tokens",
  audit: "/audit",
  settings: "/settings",
};
const pageAt = (pathname: string) =>
  (Object.keys(paths) as Page[]).find((p) => paths[p] === pathname) ??
  "overview";
// Storage can be unavailable (private windows, sandboxed frames); the choice then lasts
// only until the next reload.
const remembered = {
  get(key: string) {
    try {
      return localStorage.getItem(key) ?? "";
    } catch {
      return "";
    }
  },
  set(key: string, value: string) {
    try {
      localStorage.setItem(key, value);
    } catch {
      // Not persisted.
    }
  },
};

function Workspace({ user, signedOut }: { user: User; signedOut: () => void }) {
  const [page, setPage] = useState<Page>(() => pageAt(location.pathname));
  const spaceKey = `assh.space.${user.id}`;
  const [space, setSpace] = useState(() => remembered.get(spaceKey));
  const [revision, setRevision] = useState(0);
  const refresh = () => setRevision((v) => v + 1);
  const [modal, setModal] = useState<"device" | "team" | "guide" | null>(null);
  const [detail, setDetail] = useState<Device | null>(null);
  const [edit, setEdit] = useState<Device | null>(null);
  const [query, setQuery] = useState("");
  const [mobile, setMobile] = useState(false);
  const [notice, setNotice] = useState("");
  const {
    data: teams,
    error: teamError,
    loading: teamsLoading,
    retry: retryTeams,
  } = useResource<Team[]>("/teams", revision);
  const {
    data: devices,
    error: deviceError,
    loading: devicesLoading,
    retry: retryDevices,
  } = useResource<Device[]>("/devices", revision);
  const team = teams?.find((t) => t.id === space);
  const canManage = !space || team?.role === "owner" || team?.role === "admin";
  // Wait for the team list before choosing between the team log and the personal log.
  const { data: events } = useResource<Audit[]>(
    space && !team
      ? null
      : team && canManage
        ? `/audit?team=${space}`
        : "/audit",
    revision,
  );
  const scoped =
    devices?.filter((d) => (space ? d.team_id === space : !d.team_id)) ?? [];
  const filtered = scoped.filter((d) =>
    `${d.name} ${d.host} ${d.username}`
      .toLowerCase()
      .includes(query.toLowerCase()),
  );
  const show = (target: Page) => {
    setPage(target);
    setMobile(false);
    setQuery("");
  };
  const navigate = (target: Page) => {
    if (location.pathname !== paths[target])
      history.pushState(null, "", paths[target]);
    show(target);
  };
  useEffect(() => {
    const back = () => show(pageAt(location.pathname));
    window.addEventListener("popstate", back);
    return () => window.removeEventListener("popstate", back);
  }, []);
  const title =
    page === "settings"
      ? "账号设置"
      : navigation.find((n) => n.id === page)!.label;
  useEffect(() => {
    document.title = `${title} · AsshManager`;
    return () => {
      document.title = "AsshManager";
    };
  }, [title]);
  useEffect(() => remembered.set(spaceKey, space), [spaceKey, space]);
  // A remembered team the user has since left falls back to the personal workspace. Check only
  // the first team list: right after creating a team, the list is briefly stale.
  const checkedSpace = useRef(false);
  useEffect(() => {
    if (!teams || checkedSpace.current) return;
    checkedSpace.current = true;
    if (!teams.some((t) => t.id === space)) setSpace("");
  }, [teams, space]);
  const completed = (message?: string) => {
    refresh();
    if (message) setNotice(message);
  };
  useEffect(() => {
    if (!notice) return;
    const timer = setTimeout(() => setNotice(""), 5000);
    return () => clearTimeout(timer);
  }, [notice]);
  const workspaceName = (teamId: string | null) =>
    teams?.find((t) => t.id === teamId)?.name ?? "个人工作空间";
  const online = scoped.filter((d) => d.status === "online").length;
  const failed = scoped.filter((d) => d.status === "failed").length;
  // Each SSH operation logs "started" before its result, and sign-ins say nothing about the
  // workspace. The personal log also holds the user's team actions, so keep this workspace's.
  // Repeats in a row, such as browsing several folders on one server, share one line.
  const recent: (Audit & { count: number })[] = [];
  for (const e of events ?? []) {
    if (
      e.outcome === "started" ||
      e.action === "account.login" ||
      (e.team_id ?? "") !== space
    )
      continue;
    const last = recent.at(-1);
    if (
      last &&
      last.action === e.action &&
      last.actor_name === e.actor_name &&
      last.target === e.target &&
      last.outcome === e.outcome
    )
      last.count++;
    else if (recent.length < 5) recent.push({ ...e, count: 1 });
    else break;
  }
  function serverTable() {
    const overview = page === "overview";
    const rows = overview ? scoped.slice(0, 5) : filtered;
    // Owners, admins, and personal servers always show "管理"; the column only helps members.
    const showAccess = rows.some((d) => d.access !== "manage");
    return (
      <div className="panel server-panel">
        {overview ? (
          <div className="table-heading">
            <h3>服务器</h3>
            {scoped.length > rows.length && (
              <button
                className="text-button"
                onClick={() => navigate("devices")}
              >
                查看全部 {scoped.length} 台 <ArrowRight size={15} />
              </button>
            )}
          </div>
        ) : (
          scoped.length > 0 && (
            <div className="table-toolbar">
              <div className="search">
                <Search size={16} />
                <input
                  aria-label="搜索服务器"
                  placeholder="搜索名称、主机或用户"
                  value={query}
                  onChange={(e) => setQuery(e.target.value)}
                />
              </div>
            </div>
          )
        )}
        {devicesLoading ? (
          <Loading />
        ) : !devices ? null : !rows.length ? (
          <Empty
            title={
              scoped.length
                ? "没有匹配的服务器"
                : canManage
                  ? "还没有服务器"
                  : "暂无可访问的服务器"
            }
          />
        ) : (
          <div className="table-scroll">
            <table>
              <thead>
                <tr>
                  <th>服务器</th>
                  <th>状态</th>
                  {showAccess && <th className="optional">权限</th>}
                  <th className="optional">最近检测</th>
                  <th>
                    <span className="sr-only">操作</span>
                  </th>
                </tr>
              </thead>
              <tbody>
                {rows.map((device) => (
                  <tr
                    key={device.id}
                    className="server-row"
                    onClick={(e) => {
                      if (!(e.target as HTMLElement).closest("button"))
                        setDetail(device);
                    }}
                  >
                    <td className="server-cell">
                      <button
                        className="server-name"
                        onClick={() => setDetail(device)}
                      >
                        <span className="server-icon">
                          <Server size={17} />
                        </span>
                        <span className="server-meta">
                          <strong>{device.name}</strong>
                          <small>
                            {device.username}@{device.host}:{device.port}
                          </small>
                        </span>
                      </button>
                    </td>
                    <td>
                      <Status value={device.status} />
                    </td>
                    {showAccess && (
                      <td className="optional">
                        <span className="permission-label">
                          <ShieldCheck size={14} />
                          {roleNames[device.access]}
                        </span>
                      </td>
                    )}
                    <td className="muted optional">
                      {date(device.checked_at)}
                    </td>
                    <td className="row-end">
                      <button
                        className="row-action"
                        onClick={() => setDetail(device)}
                        aria-label={`打开 ${device.name}`}
                      >
                        <ChevronRight size={17} />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    );
  }
  return (
    <div className="workspace">
      <aside className={`sidebar ${mobile ? "mobile-open" : ""}`}>
        <Brand />
        <button
          className="mobile-close icon-button"
          aria-label="关闭导航"
          onClick={() => setMobile(false)}
        >
          <X />
        </button>
        <div className="workspace-picker">
          <Select
            ariaLabel="切换工作空间"
            variant="workspace"
            value={space}
            onChange={(next) => {
              setSpace(next);
              setDetail(null);
              setQuery("");
            }}
            options={[
              {
                value: "",
                label: "个人工作空间",
                icon: (
                  <span className="workspace-avatar">
                    {user.name.slice(0, 1).toUpperCase()}
                  </span>
                ),
              },
              ...(teams?.map((t) => ({
                value: t.id,
                label: t.name,
                icon: (
                  <span className="workspace-avatar">
                    <Users size={16} />
                  </span>
                ),
              })) ?? []),
            ]}
          />
        </div>
        <nav>
          {navigation.map((item) => (
            <button
              key={item.id}
              className={page === item.id ? "nav-item active" : "nav-item"}
              onClick={() => navigate(item.id)}
            >
              <item.icon size={18} />
              <span>{item.label}</span>
            </button>
          ))}
        </nav>
        <button
          className="new-team"
          onClick={() => {
            setModal("team");
            setMobile(false);
          }}
        >
          <Plus size={16} /> 创建团队
        </button>
        <div className="sidebar-bottom">
          <button
            className={`nav-item ${page === "settings" ? "active" : ""}`}
            onClick={() => navigate("settings")}
          >
            <Settings size={18} />
            账号设置
          </button>
          <button className="nav-item" onClick={() => setModal("guide")}>
            <CircleHelp size={18} />
            使用指南
          </button>
          <div className="user-profile">
            <span className="avatar">
              {user.name.slice(0, 1).toUpperCase()}
            </span>
            <span>
              <strong>{user.name}</strong>
              <small>{user.email}</small>
            </span>
            <button
              className="icon-button"
              aria-label="退出登录"
              onClick={async () => {
                try {
                  await api("/auth/logout", "POST");
                  history.replaceState(null, "", "/");
                  signedOut();
                } catch (e) {
                  setNotice((e as Error).message);
                }
              }}
            >
              <LogOut size={17} />
            </button>
          </div>
        </div>
      </aside>
      {mobile && (
        <button
          aria-label="关闭侧边栏"
          className="sidebar-overlay"
          onClick={() => setMobile(false)}
        />
      )}
      <div className="workspace-body">
        {/* Narrow screens only: the sidebar with the workspace picker is hidden there. */}
        <header className="topbar">
          <button
            className="icon-button mobile-menu"
            aria-label="打开导航"
            onClick={() => setMobile(true)}
          >
            <Menu size={21} />
          </button>
          <span>{team?.name ?? "个人工作空间"}</span>
        </header>
        <main>
          <ErrorBox
            onRetry={
              teamError || deviceError
                ? () => {
                    if (teamError) retryTeams();
                    if (deviceError) retryDevices();
                  }
                : undefined
            }
          >
            {teamError || deviceError}
          </ErrorBox>
          {(page === "overview" || page === "devices") && (
            <>
              <div className="page-heading">
                <h1>
                  {page === "overview" ? (
                    "工作台"
                  ) : (
                    <>
                      服务器
                      {devices && (
                        <span className="count">{scoped.length}</span>
                      )}
                    </>
                  )}
                </h1>
                {canManage && (
                  <button
                    className="button primary"
                    onClick={() => setModal("device")}
                  >
                    <Plus size={16} /> 添加服务器
                  </button>
                )}
              </div>
              {page === "overview" && scoped.length > 0 && (
                <div className="stats-grid">
                  <Stat
                    icon={Server}
                    tone="blue"
                    label="服务器"
                    value={devices && scoped.length}
                  />
                  <Stat
                    icon={CircleCheck}
                    tone="green"
                    label="连接成功"
                    value={devices && online}
                  />
                  <Stat
                    icon={CircleAlert}
                    tone={failed ? "red" : "gray"}
                    label="连接失败"
                    value={devices && failed}
                  />
                  <Stat
                    icon={Users}
                    tone="purple"
                    label={space ? "团队成员" : "我的团队"}
                    value={
                      teams &&
                      (space ? (team?.member_count ?? 0) : teams.length)
                    }
                  />
                </div>
              )}
              {serverTable()}
              {page === "overview" && (
                <section className="panel activity-panel">
                  <div className="section-heading">
                    <h3>最近活动</h3>
                    <button
                      className="text-button"
                      onClick={() => navigate("audit")}
                    >
                      全部日志 <ArrowRight size={14} />
                    </button>
                  </div>
                  {recent.length ? (
                    recent.map((event) => (
                      <div className="activity-row" key={event.id}>
                        <span
                          className={`activity-dot ${event.outcome}`}
                          aria-hidden="true"
                        />
                        <div>
                          <strong>
                            {actionNames[event.action] ?? event.action}
                            {event.count > 1 && (
                              <span className="activity-count">
                                ×{event.count}
                              </span>
                            )}
                          </strong>
                          <p>
                            {event.actor_name}
                            {event.target !== event.actor_name &&
                              ` · ${event.target}`}
                          </p>
                        </div>
                        <span className="activity-time">
                          {date(event.created_at)}
                        </span>
                      </div>
                    ))
                  ) : (
                    <p className="activity-empty">暂无活动</p>
                  )}
                </section>
              )}
            </>
          )}
          {page === "teams" && (
            <TeamPage
              teams={teams ?? []}
              team={team}
              user={user}
              revision={revision}
              select={setSpace}
              create={() => setModal("team")}
              changed={completed}
            />
          )}
          {page === "tokens" && (
            <TokenPage revision={revision} changed={completed} />
          )}
          {page === "audit" && (
            <AuditPage
              team={canManage ? team : undefined}
              revision={revision}
            />
          )}
          {page === "settings" && (
            <SettingsPage user={user} changed={completed} />
          )}
        </main>
      </div>
      {notice && (
        <div className="toast" role="status">
          {notice}
          <button aria-label="关闭提示" onClick={() => setNotice("")}>
            <X size={15} />
          </button>
        </div>
      )}
      {modal === "device" && (
        <DeviceForm
          teamId={space || null}
          workspace={workspaceName(space || null)}
          close={() => setModal(null)}
          saved={() => {
            setModal(null);
            completed("服务器已添加");
          }}
        />
      )}
      {edit && (
        <DeviceForm
          device={edit}
          teamId={edit.team_id}
          workspace={workspaceName(edit.team_id)}
          close={() => setEdit(null)}
          saved={() => {
            setEdit(null);
            setDetail(null);
            completed("服务器已更新");
          }}
        />
      )}
      {detail && !edit && (
        <DeviceDetail
          device={devices?.find((d) => d.id === detail.id) ?? detail}
          close={() => setDetail(null)}
          edit={() => setEdit(detail)}
          changed={completed}
          removed={() => {
            setDetail(null);
            completed("服务器已删除");
          }}
        />
      )}
      {modal === "team" && (
        <Modal title="创建团队" close={() => setModal(null)}>
          <Form
            label="创建团队"
            cancel={() => setModal(null)}
            submit={async (form) => {
              const team = await api<Team>(
                "/teams",
                "POST",
                Object.fromEntries(form),
              );
              setSpace(team.id);
              setModal(null);
              navigate("teams");
              completed("团队已创建");
            }}
          >
            <label>
              团队名称
              <input name="name" maxLength={80} required data-autofocus />
            </label>
          </Form>
        </Modal>
      )}
      {modal === "guide" && (
        <Modal title="使用指南" close={() => setModal(null)} wide>
          <Guide />
        </Modal>
      )}
    </div>
  );
}
function Stat({
  icon: Icon,
  tone,
  label,
  value,
}: {
  icon: typeof Server;
  tone: string;
  label: string;
  value: number | undefined;
}) {
  return (
    <div className="stat-card">
      <span className={`stat-icon ${tone}`}>
        <Icon size={19} />
      </span>
      <div>
        <span>{label}</span>
        <strong>{value ?? "—"}</strong>
      </div>
    </div>
  );
}
function App() {
  const [user, setUser] = useState<User | null>();
  const [error, setError] = useState("");
  const [bootNonce, setBootNonce] = useState(0);
  const readAction = (): EmailAction | null => {
    const params = new URLSearchParams(window.location.hash.slice(1));
    const action = params.get("action"),
      token = params.get("token");
    return token &&
      (action === "verify" || action === "reset" || action === "invite")
      ? { action, token }
      : null;
  };
  const [action, setAction] = useState(readAction);
  useEffect(() => {
    const receive = () => {
      setAction(readAction());
      history.replaceState(null, "", window.location.pathname);
    };
    history.replaceState(null, "", window.location.pathname);
    window.addEventListener("hashchange", receive);
    return () => window.removeEventListener("hashchange", receive);
  }, []);
  useEffect(() => {
    const controller = new AbortController();
    setError("");
    setUser(undefined);
    api<User>("/me", "GET", undefined, controller.signal)
      .then((value) => {
        if (!controller.signal.aborted) setUser(value);
      })
      .catch((err) => {
        if (controller.signal.aborted) return;
        if (err.message !== "请先登录") setError(err.message);
        setUser(null);
      });
    return () => controller.abort();
  }, [bootNonce]);
  useEffect(() => {
    const expired = () => setUser(null);
    window.addEventListener("session-expired", expired);
    return () => window.removeEventListener("session-expired", expired);
  }, []);
  const {
    data: config,
    error: configError,
    loading: configLoading,
    retry: retryConfig,
  } = useResource<PublicConfig>("/public-config", bootNonce);
  if (configError)
    return (
      <main className="auth-page">
        <Brand />
        <div className="auth-card">
          <ErrorBox
            onRetry={() => {
              retryConfig();
              setBootNonce((n) => n + 1);
            }}
          >
            {configError}
          </ErrorBox>
        </div>
      </main>
    );
  if (user === undefined || configLoading || !config)
    return (
      <div className="app-loading">
        <Loading />
      </div>
    );
  return user &&
    (!config.emailVerificationRequired || user.email_verified) &&
    !action ? (
    <Workspace user={user} signedOut={() => setUser(null)} />
  ) : (
    <>
      <ErrorBox onRetry={error ? () => setBootNonce((n) => n + 1) : undefined}>
        {error}
      </ErrorBox>
      <Auth
        user={user}
        action={action}
        verificationRequired={config.emailVerificationRequired}
        cancel={() => setAction(null)}
        finished={(next, completeAction) => {
          setError("");
          setUser(next);
          if (completeAction) setAction(null);
        }}
      />
    </>
  );
}
createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);
