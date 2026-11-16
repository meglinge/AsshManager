import { useState } from "react";
import {
  ArrowUp,
  Check,
  FileText,
  Fingerprint,
  Folder,
  KeyRound,
  LockKeyhole,
  Play,
  Server,
  Settings,
  ShieldCheck,
  Terminal,
  Trash2,
  Users,
} from "lucide-react";
import {
  api,
  useResource,
  type Device,
  type Member,
  Modal,
  Form,
  ErrorBox,
  Loading,
  Status,
  CopyButton,
  Select,
  roleNames,
  date,
  useConfirm,
} from "./common";

export function DeviceForm({
  device,
  teamId,
  workspace,
  close,
  saved,
}: {
  device?: Device;
  teamId: string | null;
  workspace: string;
  close: () => void;
  saved: () => void;
}) {
  const [auth, setAuth] = useState(device?.auth_type ?? "key");
  const keepsCredential = device?.auth_type === auth;
  return (
    <Modal
      title={device ? "编辑服务器" : "添加服务器"}
      description={workspace}
      close={close}
      wide
    >
      <Form
        label={device ? "保存更改" : "添加服务器"}
        cancel={close}
        submit={async (form) => {
          const values = Object.fromEntries(form);
          await api(
            `/devices${device ? `/${device.id}` : ""}`,
            device ? "PUT" : "POST",
            {
              ...values,
              team_id: teamId,
              port: Number(values.port),
              auth_type: auth,
              password: values.password || undefined,
              privateKey: values.privateKey || undefined,
              passphrase: values.passphrase || undefined,
            },
          );
          saved();
        }}
      >
        <div className="form-section-title">
          <Server size={17} /> 基本信息
        </div>
        <div className="form-grid">
          <label>
            服务器名称
            <input
              name="name"
              defaultValue={device?.name}
              placeholder="production-api-01"
              maxLength={80}
              required
              data-autofocus
            />
          </label>
          <label>
            主机地址
            <input
              name="host"
              defaultValue={device?.host}
              placeholder="203.0.113.10 或 ssh.example.com"
              required
            />
          </label>
          <label>
            SSH 端口
            <input
              name="port"
              type="number"
              min={1}
              max={65535}
              defaultValue={device?.port ?? 22}
              required
            />
          </label>
          <label>
            SSH 用户名
            <input
              name="username"
              defaultValue={device?.username}
              placeholder="deploy"
              required
              autoComplete="off"
            />
          </label>
          <label>
            备注（可选）
            <input name="note" defaultValue={device?.note} maxLength={1000} />
          </label>
        </div>
        <div className="form-section-title">
          <KeyRound size={17} /> SSH 认证
        </div>
        <div className="segmented">
          <button
            type="button"
            className={auth === "key" ? "active" : ""}
            onClick={() => setAuth("key")}
          >
            <KeyRound size={15} /> 私钥认证
          </button>
          <button
            type="button"
            className={auth === "password" ? "active" : ""}
            onClick={() => setAuth("password")}
          >
            <LockKeyhole size={15} /> 密码认证
          </button>
        </div>
        {auth === "key" ? (
          <>
            <label>
              SSH 私钥{keepsCredential && "（留空则保留原私钥）"}
              <textarea
                name="privateKey"
                className="mono"
                placeholder="-----BEGIN OPENSSH PRIVATE KEY-----"
                rows={3}
                required={!keepsCredential}
                autoComplete="off"
                spellCheck={false}
              />
            </label>
            <label>
              私钥口令（可选{keepsCredential && "，仅随新私钥保存"}）
              <input
                name="passphrase"
                type="password"
                autoComplete="new-password"
              />
            </label>
          </>
        ) : (
          <label>
            SSH 密码{keepsCredential && "（留空则保留原密码）"}
            <input
              name="password"
              type="password"
              autoComplete="new-password"
              required={!keepsCredential}
            />
          </label>
        )}
        <div className="form-section-title">
          <Fingerprint size={17} /> 主机指纹
        </div>
        <label>
          SHA256 指纹
          <input
            name="fingerprint"
            className="mono"
            defaultValue={device?.fingerprint}
            placeholder="SHA256:…"
            pattern="SHA256:[A-Za-z0-9+/]{43}"
            required
          />
        </label>
        <p className="field-help">在服务器本机执行以下命令获取：</p>
        <div className="inline-code">
          <code>{fingerprintCommand}</code>
          <CopyButton value={fingerprintCommand} />
        </div>
      </Form>
    </Modal>
  );
}
const fingerprintCommand =
  "ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub -E sha256";

function Permissions({
  device,
  changed,
}: {
  device: Device;
  changed: (message?: string) => void;
}) {
  const [revision, setRevision] = useState(0);
  // Unsaved selections by grant subject; "*" is every team member.
  const [draft, setDraft] = useState<Record<string, string>>({});
  const {
    data: members,
    error,
    loading: membersLoading,
    retry: retryMembers,
  } = useResource<Member[]>(`/teams/${device.team_id}/members`, revision);
  const {
    data: grants,
    error: grantError,
    loading: grantsLoading,
    retry: retryGrants,
  } = useResource<{ subject: string; level: string }[]>(
    `/devices/${device.id}/grants`,
    revision,
  );
  if (error || grantError)
    return (
      <ErrorBox
        onRetry={() => {
          if (error) retryMembers();
          if (grantError) retryGrants();
        }}
      >
        {error || grantError}
      </ErrorBox>
    );
  if (membersLoading || grantsLoading || !members || !grants)
    return <Loading />;
  const saved = (subject: string) =>
    grants.find((g) => g.subject === subject)?.level ?? "none";
  const level = (subject: string) => draft[subject] ?? saved(subject);
  const choose = (subject: string, value: string) => {
    setDraft((d) => ({ ...d, [subject]: value }));
  };
  // A member gets the higher of their own grant and the all-member grant, so 仅查看 under an
  // all-member 可执行 does nothing. Say so only when someone is set up that way.
  const overridden =
    level("*") === "execute"
      ? members.filter((m) => m.role === "member" && level(m.id) === "view")
      : [];
  return (
    <Form
      key={revision}
      label="保存访问权限"
      submit={async (form) => {
        const data = Array.from(form)
          .filter(([, value]) => value !== "none")
          .map(([subject, level]) => ({ subject, level }));
        await api(`/devices/${device.id}/grants`, "PUT", data);
        setDraft({});
        setRevision((r) => r + 1);
        changed("访问权限已更新");
      }}
    >
      <div className="permission-row all-members">
        <span className="avatar">
          <Users size={18} />
        </span>
        <div>
          <strong>全体团队成员</strong>
        </div>
        <Select
          name="*"
          ariaLabel="全体团队成员权限"
          variant="compact"
          align="right"
          defaultValue={saved("*")}
          onChange={(value) => choose("*", value)}
          options={[
            { value: "none", label: "不授权" },
            { value: "view", label: "仅查看" },
            { value: "execute", label: "可执行" },
          ]}
        />
      </div>
      {members.map((member) => (
        <div className="permission-row" key={member.id}>
          <span className="avatar">{member.name.slice(0, 1)}</span>
          <div>
            <strong>{member.name}</strong>
            <small>{member.email}</small>
          </div>
          {member.role !== "member" ? (
            <span className="tag neutral">{roleNames[member.role]}</span>
          ) : (
            <Select
              name={member.id}
              ariaLabel={`${member.name} 权限`}
              variant="compact"
              align="right"
              defaultValue={saved(member.id)}
              onChange={(value) => choose(member.id, value)}
              options={[
                { value: "none", label: "不单独授权" },
                { value: "view", label: "仅查看" },
                { value: "execute", label: "可执行" },
              ]}
            />
          )}
        </div>
      ))}
      {overridden.length > 0 && (
        <p className="warning-box" role="status">
          已为全体团队成员授予「可执行」，
          {overridden.map((m) => m.name).join("、")}的「仅查看」不会生效。
        </p>
      )}
    </Form>
  );
}

interface CommandResult {
  stdout: string;
  stderr: string;
  exitCode: number | null;
  signal: string | null;
}
function CommandPanel({
  device,
  changed,
}: {
  device: Device;
  changed: (message?: string) => void;
}) {
  const [result, setResult] = useState<CommandResult>();
  return (
    <>
      <Form
        label="执行"
        submit={async (form) => {
          setResult(undefined);
          setResult(
            await api<CommandResult>(`/devices/${device.id}/run`, "POST", {
              operation: "execute",
              command: form.get("command"),
              timeout: Number(form.get("timeout")),
            }),
          );
          changed();
        }}
      >
        <label>
          命令
          <textarea
            name="command"
            className="mono"
            placeholder="uname -a && uptime"
            rows={3}
            maxLength={8192}
            required
            spellCheck={false}
            autoFocus
            aria-keyshortcuts="Control+Enter Meta+Enter"
            onKeyDown={(e) => {
              if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) {
                e.preventDefault();
                e.currentTarget.form?.requestSubmit();
              }
            }}
          />
        </label>
        <label className="short-field">
          超时（秒）
          <input
            name="timeout"
            type="number"
            min={1}
            max={60}
            defaultValue={30}
            required
          />
        </label>
      </Form>
      <div aria-live="polite">
        {result && (
          <div className="terminal-output">
            <div className="terminal-header">
              <span>
                {device.username}@{device.host}
              </span>
              <span className={result.exitCode === 0 ? "exit ok" : "exit"}>
                exit {result.exitCode ?? result.signal ?? "?"}
              </span>
            </div>
            <pre>
              {result.stdout}
              {result.stderr && (
                <span className="stderr">
                  {result.stdout && !result.stdout.endsWith("\n") && "\n"}
                  {result.stderr}
                </span>
              )}
              {!result.stdout && !result.stderr && (
                <span className="quiet">（无输出）</span>
              )}
            </pre>
          </div>
        )}
      </div>
    </>
  );
}

type FileResult =
  | {
      entries: {
        name: string;
        size: number;
        directory: boolean;
        modifiedAt: string;
      }[];
      truncated: boolean;
    }
  | { content: string; bytes: number }
  | { written: true; bytes: number };
const size = (bytes: number) =>
  bytes < 1024
    ? `${bytes} B`
    : bytes < 1048576
      ? `${(bytes / 1024).toFixed(1)} KiB`
      : `${(bytes / 1048576).toFixed(1)} MiB`;

type FileOperation = "list_directory" | "read_file" | "write_file";
const parentOf = (path: string) =>
  path.replace(/\/+$/, "").replace(/\/[^/]*$/, "") || "/";
const childOf = (path: string, name: string) =>
  `${path.replace(/\/+$/, "")}/${name}`;

function FileView({
  path,
  data,
  open,
}: {
  path: string;
  data: FileResult;
  open: (operation: FileOperation, path: string) => void;
}) {
  if ("written" in data)
    return (
      <p className="file-written">
        <Check size={16} /> 已写入 {path}（{size(data.bytes)}）
      </p>
    );
  const header = (summary: string) => (
    <div className="file-result-header">
      {path !== "/" && (
        <button
          type="button"
          className="icon-button"
          aria-label="上级目录"
          title="上级目录"
          onClick={() => open("list_directory", parentOf(path))}
        >
          <ArrowUp size={16} />
        </button>
      )}
      <code>{path}</code>
      <span>{summary}</span>
    </div>
  );
  if ("content" in data)
    return (
      <div className="file-result">
        {header(size(data.bytes))}
        <pre>{data.content || "（空文件）"}</pre>
      </div>
    );
  const entries = [...data.entries].sort(
    (a, b) =>
      Number(b.directory) - Number(a.directory) || a.name.localeCompare(b.name),
  );
  return (
    <div className="file-result">
      {header(data.truncated ? "仅显示前 1000 项" : `${entries.length} 项`)}
      {entries.length ? (
        <div className="table-scroll">
          <table className="file-table">
            <thead>
              <tr>
                <th>名称</th>
                <th>大小</th>
                <th>修改时间</th>
              </tr>
            </thead>
            <tbody>
              {entries.map((entry) => (
                <tr key={entry.name}>
                  <td>
                    <button
                      type="button"
                      className="file-name"
                      onClick={() =>
                        open(
                          entry.directory ? "list_directory" : "read_file",
                          childOf(path, entry.name),
                        )
                      }
                    >
                      {entry.directory ? (
                        <Folder size={15} />
                      ) : (
                        <FileText size={15} />
                      )}
                      {entry.name}
                      {entry.directory && "/"}
                    </button>
                  </td>
                  <td className="muted">
                    {entry.directory ? "—" : size(entry.size)}
                  </td>
                  <td className="muted">{date(entry.modifiedAt)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <p className="file-empty">空目录</p>
      )}
    </div>
  );
}

function FilePanel({
  device,
  changed,
}: {
  device: Device;
  changed: (message?: string) => void;
}) {
  const [operation, setOperation] = useState<FileOperation>("list_directory");
  const [path, setPath] = useState(
    device.username === "root" ? "/root" : `/home/${device.username}`,
  );
  const [result, setResult] = useState<{ path: string; data: FileResult }>();
  const [opening, setOpening] = useState(false);
  const [openError, setOpenError] = useState("");
  const [confirmDialog, confirm] = useConfirm();
  async function run(
    next: FileOperation,
    target: string,
    write?: { content: FormDataEntryValue | null; overwrite: boolean },
  ) {
    setResult(undefined);
    setOpenError("");
    const data = await api<FileResult>(`/devices/${device.id}/run`, "POST", {
      operation: next,
      path: target,
      ...write,
    });
    setResult({ path: target, data });
    changed();
  }
  // Entries and the parent button run outside the form, so they report their own errors.
  function open(next: FileOperation, target: string) {
    setOperation(next);
    setPath(target);
    setOpening(true);
    run(next, target)
      .catch((error) => setOpenError((error as Error).message))
      .finally(() => setOpening(false));
  }
  return (
    <>
      <Form
        label={
          operation === "write_file"
            ? "写入"
            : operation === "read_file"
              ? "读取"
              : "打开"
        }
        submit={async (form) => {
          if (operation !== "write_file") return run(operation, path);
          if (
            await confirm({
              title: `写入 ${path}？`,
              action: "写入",
            })
          )
            await run(operation, path, {
              content: form.get("content"),
              overwrite: form.get("overwrite") === "on",
            });
        }}
      >
        <div className="form-grid file-controls">
          <div className="field">
            <span className="field-label">操作</span>
            <Select
              ariaLabel="操作"
              value={operation}
              onChange={(next) => {
                setOperation(next as FileOperation);
                setResult(undefined);
                setOpenError("");
              }}
              options={[
                { value: "list_directory", label: "浏览目录" },
                { value: "read_file", label: "读取文件" },
                { value: "write_file", label: "写入文件" },
              ]}
            />
          </div>
          <label>
            路径
            <input
              name="path"
              value={path}
              onChange={(e) => setPath(e.target.value)}
              required
              pattern="/.*"
              title="以 / 开头的绝对路径"
              spellCheck={false}
            />
          </label>
        </div>
        {operation === "write_file" && (
          <>
            <label>
              文件内容
              <textarea
                name="content"
                rows={5}
                className="mono"
                maxLength={65536}
                spellCheck={false}
              />
            </label>
            <label className="checkbox">
              <input name="overwrite" type="checkbox" />
              覆盖已有文件
            </label>
          </>
        )}
      </Form>
      {confirmDialog}
      {opening && <Loading />}
      <ErrorBox>{openError}</ErrorBox>
      {result && <FileView {...result} open={open} />}
    </>
  );
}

export function DeviceDetail({
  device,
  close,
  edit,
  changed,
  removed,
}: {
  device: Device;
  close: () => void;
  edit: () => void;
  changed: (message?: string) => void;
  removed: () => void;
}) {
  const [tab, setTab] = useState("overview");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [confirmDialog, confirm] = useConfirm();
  const tabs = [
    { id: "overview", label: "概览", icon: Server },
    ...(device.access !== "view"
      ? [
          { id: "terminal", label: "终端", icon: Terminal },
          { id: "files", label: "文件", icon: FileText },
        ]
      : []),
    ...(device.access === "manage" && device.team_id
      ? [{ id: "permissions", label: "访问权限", icon: ShieldCheck }]
      : []),
  ];
  return (
    <Modal
      title={device.name}
      description={
        <span className="mono">
          {device.username}@{device.host}:{device.port}
        </span>
      }
      close={close}
      wide
    >
      <div className="detail-tabs">
        {tabs.map((t) => (
          <button
            key={t.id}
            className={tab === t.id ? "active" : ""}
            onClick={() => setTab(t.id)}
          >
            <t.icon size={16} />
            {t.label}
          </button>
        ))}
      </div>
      {tab === "overview" && (
        <>
          <dl className="detail-grid">
            <div>
              <dt>状态</dt>
              <dd>
                <Status value={device.status} />
              </dd>
            </div>
            <div>
              <dt>最近检测</dt>
              <dd>{date(device.checked_at)}</dd>
            </div>
            <div>
              <dt>SSH 长连接</dt>
              <dd>
                {device.connection?.state === "connected"
                  ? `已保持 · 自 ${date(device.connection.since)}`
                  : device.connection
                    ? "正在建立"
                    : "未建立"}
              </dd>
            </div>
            <div>
              <dt>我的权限</dt>
              <dd>{roleNames[device.access]}</dd>
            </div>
            <div>
              <dt>认证方式</dt>
              <dd>{device.auth_type === "key" ? "私钥" : "密码"}</dd>
            </div>
            {device.note && (
              <div className="wide">
                <dt>备注</dt>
                <dd>{device.note}</dd>
              </div>
            )}
            <div className="wide">
              <dt>主机指纹</dt>
              <dd className="mono">{device.fingerprint}</dd>
            </div>
          </dl>
          <div className="detail-actions">
            <button
              className="button primary"
              disabled={busy}
              onClick={async () => {
                setBusy(true);
                setError("");
                try {
                  await api(`/devices/${device.id}/run`, "POST", {
                    operation: "ping",
                  });
                  changed("连接成功");
                } catch (error) {
                  setError((error as Error).message);
                  changed();
                } finally {
                  setBusy(false);
                }
              }}
            >
              <Play size={15} />
              {busy ? "正在连接…" : "测试连接"}
            </button>
            {device.access === "manage" && (
              <button className="button secondary" onClick={edit}>
                <Settings size={15} />
                编辑
              </button>
            )}
            <CopyButton value={device.id} label="复制服务器 ID" />
          </div>
          <ErrorBox>{error}</ErrorBox>
          {device.access === "manage" && (
            <div className="danger-zone">
              <button
                className="button danger small"
                disabled={busy}
                onClick={async () => {
                  if (
                    !(await confirm({
                      title: `删除 ${device.name}？`,
                      action: "删除",
                    }))
                  )
                    return;
                  setBusy(true);
                  try {
                    await api(`/devices/${device.id}`, "DELETE");
                    removed();
                  } catch (e) {
                    setError((e as Error).message);
                  } finally {
                    setBusy(false);
                  }
                }}
              >
                <Trash2 size={14} />
                删除服务器
              </button>
            </div>
          )}
        </>
      )}
      {tab === "terminal" && <CommandPanel device={device} changed={changed} />}
      {tab === "files" && <FilePanel device={device} changed={changed} />}
      {tab === "permissions" && (
        <Permissions device={device} changed={changed} />
      )}
      {confirmDialog}
    </Modal>
  );
}
