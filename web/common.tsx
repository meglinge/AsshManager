import {
  useEffect,
  useLayoutEffect,
  useRef,
  useState,
  type FormEvent,
  type KeyboardEvent,
  type ReactNode,
} from "react";
import {
  X,
  LoaderCircle,
  Inbox,
  Check,
  Copy,
  ChevronDown,
  RotateCw,
} from "lucide-react";

export interface PublicConfig {
  mailMode: string;
  emailVerificationRequired: boolean;
}
export interface User {
  id: string;
  name: string;
  email: string;
  email_verified: boolean;
}
export interface Team {
  id: string;
  name: string;
  role: string;
  member_count: number;
}
export interface Member extends User {
  role: string;
}
export interface Device {
  id: string;
  name: string;
  host: string;
  port: number;
  username: string;
  team_id: string | null;
  note: string;
  fingerprint: string;
  auth_type: string;
  status: string;
  access: "view" | "execute" | "manage";
  checked_at: string | null;
  created_at: string;
}
export interface Audit {
  id: number;
  team_id: string | null;
  action: string;
  target: string;
  actor_name: string;
  outcome: string;
  source: string;
  created_at: string;
  detail: string;
}
export const roleNames: Record<string, string> = {
  owner: "所有者",
  admin: "管理员",
  member: "成员",
  manage: "管理",
  execute: "可执行",
  view: "仅查看",
};
export const actionNames: Record<string, string> = {
  "account.register": "注册账号",
  "account.login": "登录账号",
  "account.password": "修改密码",
  "account.verify": "验证邮箱",
  "account.reset": "重置密码",
  "team.create": "创建团队",
  "team.invite": "发送团队邀请",
  "team.invite.revoke": "撤销团队邀请",
  "team.member.add": "添加成员",
  "team.member.remove": "移除成员",
  "device.create": "添加服务器",
  "device.update": "更新服务器",
  "device.delete": "删除服务器",
  "device.permissions": "更新访问权限",
  "token.create": "创建 MCP 令牌",
  "token.revoke": "撤销 MCP 令牌",
  "ssh.ping": "测试 SSH 连接",
  "ssh.execute": "执行 SSH 命令",
  "ssh.read_file": "读取文件",
  "ssh.write_file": "写入文件",
  "ssh.list_directory": "浏览目录",
};
export const date = (value?: string | null) =>
  value
    ? new Date(value).toLocaleString("zh-CN", {
        month: "2-digit",
        day: "2-digit",
        hour: "2-digit",
        minute: "2-digit",
        hour12: false,
      })
    : "—";

const portalErrors = new Set([
  "sandbox-not-found",
  "sandbox-sleeping",
  "sandbox-starting",
  "upstream-unreachable",
]);
function friendlyError(response: Response, payload: unknown) {
  const portalError =
    response.headers.get("x-amp-portal-error") ??
    response.headers.get("x-amp-portal-proxy-error");
  const raw =
    payload &&
    typeof payload === "object" &&
    "error" in payload &&
    typeof (payload as { error: unknown }).error === "string"
      ? (payload as { error: string }).error.trim()
      : "";
  if (portalError || portalErrors.has(raw)) return "服务正在唤醒，请稍后重试";
  if (raw && /[\u4e00-\u9fff]/.test(raw)) return raw;
  if (response.status === 401) return "请先登录";
  if (response.status === 403) return "无权执行此操作";
  if (response.status === 429) return "请求过于频繁，请稍后重试";
  if (response.status >= 500) return "服务暂时不可用，请稍后重试";
  return "请求失败，请稍后重试";
}
function isTransientFailure(response: Response, payload: unknown) {
  const portalError =
    response.headers.get("x-amp-portal-error") ??
    response.headers.get("x-amp-portal-proxy-error");
  const raw =
    payload &&
    typeof payload === "object" &&
    "error" in payload &&
    typeof (payload as { error: unknown }).error === "string"
      ? (payload as { error: string }).error.trim()
      : "";
  return (
    Boolean(portalError) || portalErrors.has(raw) || response.status >= 502
  );
}
function wait(ms: number, signal?: AbortSignal) {
  return new Promise<void>((resolve, reject) => {
    const timer = setTimeout(resolve, ms);
    signal?.addEventListener(
      "abort",
      () => {
        clearTimeout(timer);
        reject(new DOMException("Aborted", "AbortError"));
      },
      { once: true },
    );
  });
}
export async function api<T>(
  path: string,
  method = "GET",
  body?: unknown,
  signal?: AbortSignal,
): Promise<T> {
  const canRetry = method === "GET";
  const delays = [900, 1800, 3200];
  for (let attempt = 0; ; attempt++) {
    let response: Response;
    try {
      response = await fetch(`/api${path}`, {
        method,
        credentials: "same-origin",
        headers:
          body === undefined ? {} : { "Content-Type": "application/json" },
        body: body === undefined ? undefined : JSON.stringify(body),
        signal,
      });
    } catch (error) {
      if ((error as Error)?.name === "AbortError") throw error;
      if (canRetry && attempt < delays.length) {
        await wait(delays[attempt], signal);
        continue;
      }
      throw new Error("网络连接异常，请检查网络后重试");
    }
    const contentType = response.headers.get("content-type") ?? "";
    let payload: unknown = null;
    if (contentType.includes("application/json")) {
      try {
        payload = await response.json();
      } catch {
        payload = null;
      }
    }
    if (!response.ok) {
      if (
        response.status === 401 &&
        !path.startsWith("/auth/") &&
        path !== "/me"
      )
        window.dispatchEvent(new Event("session-expired"));
      if (
        canRetry &&
        isTransientFailure(response, payload) &&
        attempt < delays.length
      ) {
        await wait(delays[attempt], signal);
        continue;
      }
      throw new Error(friendlyError(response, payload));
    }
    if (payload === null) {
      if (canRetry && attempt < delays.length) {
        await wait(delays[attempt], signal);
        continue;
      }
      throw new Error("服务响应异常，请刷新页面重试");
    }
    return payload as T;
  }
}
export function useResource<T>(path: string | null, revision = 0) {
  const [data, setData] = useState<T>();
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(Boolean(path));
  const [nonce, setNonce] = useState(0);
  useEffect(() => {
    const controller = new AbortController();
    setData(undefined);
    setError("");
    if (!path) {
      setLoading(false);
      return () => controller.abort();
    }
    setLoading(true);
    api<T>(path, "GET", undefined, controller.signal)
      .then((value) => {
        if (!controller.signal.aborted) {
          setData(value);
          setLoading(false);
        }
      })
      .catch((err) => {
        if (!controller.signal.aborted) {
          setError((err as Error).message || "加载失败，请稍后重试");
          setLoading(false);
        }
      });
    return () => controller.abort();
  }, [path, revision, nonce]);
  return {
    data,
    error,
    loading,
    retry: () => setNonce((n) => n + 1),
  };
}
export function Loading() {
  return (
    <div className="loading">
      <LoaderCircle className="spin" size={20} /> 加载中…
    </div>
  );
}
export function ErrorBox({
  children,
  onRetry,
}: {
  children: ReactNode;
  onRetry?: () => void;
}) {
  return children ? (
    <div className="error-box" role="alert">
      <span>{children}</span>
      {onRetry && (
        <button
          type="button"
          className="button secondary small error-retry"
          onClick={onRetry}
        >
          <RotateCw size={13} /> 重试
        </button>
      )}
    </div>
  ) : null;
}
export interface SelectOption {
  value: string;
  label: string;
  icon?: ReactNode;
}
export function Select({
  name,
  value,
  defaultValue,
  options,
  onChange,
  ariaLabel,
  variant = "default",
  align = "left",
}: {
  name?: string;
  value?: string;
  defaultValue?: string;
  options: SelectOption[];
  onChange?: (value: string) => void;
  ariaLabel?: string;
  variant?: "default" | "compact" | "workspace";
  align?: "left" | "right";
}) {
  const [internal, setInternal] = useState(
    defaultValue ?? options[0]?.value ?? "",
  );
  const current = value !== undefined ? value : internal;
  const [open, setOpen] = useState(false);
  const [activeIndex, setActiveIndex] = useState(-1);
  const rootRef = useRef<HTMLDivElement>(null);
  const triggerRef = useRef<HTMLButtonElement>(null);
  const listRef = useRef<HTMLDivElement>(null);
  const selectedIndex = Math.max(
    0,
    options.findIndex((o) => o.value === current),
  );
  const selected = options[selectedIndex] ?? options[0];

  useLayoutEffect(() => {
    if (!open) return;
    setActiveIndex(selectedIndex);
    const list = listRef.current;
    const trigger = triggerRef.current;
    if (!list || !trigger) return;
    list.showPopover?.();
    const updatePosition = () => {
      const rect = trigger.getBoundingClientRect();
      const gap = 6;
      const width = align === "right" ? Math.max(rect.width, 148) : rect.width;
      list.style.minWidth = `${width}px`;
      list.style.maxWidth = `${Math.max(width, 280)}px`;
      const naturalHeight = Math.min(252, list.scrollHeight + 2);
      const spaceBelow = window.innerHeight - rect.bottom - 12;
      const spaceAbove = rect.top - 12;
      const placeAbove = spaceBelow < naturalHeight && spaceAbove > spaceBelow;
      const maxHeight = Math.max(
        120,
        Math.min(252, placeAbove ? spaceAbove - gap : spaceBelow - gap),
      );
      const usedHeight = Math.min(naturalHeight, maxHeight);
      const rawLeft = align === "right" ? rect.right - width : rect.left;
      const left = Math.max(
        8,
        Math.min(rawLeft, window.innerWidth - width - 8),
      );
      const top = placeAbove
        ? Math.max(8, rect.top - gap - usedHeight)
        : rect.bottom + gap;
      list.style.maxHeight = `${maxHeight}px`;
      list.style.left = `${left}px`;
      list.style.top = `${top}px`;
    };
    updatePosition();
    const onPointerDown = (event: PointerEvent) => {
      if (!rootRef.current?.contains(event.target as Node)) setOpen(false);
    };
    const onReposition = (event: Event) => {
      if (event.target && list.contains(event.target as Node)) return;
      updatePosition();
    };
    document.addEventListener("pointerdown", onPointerDown);
    window.addEventListener("resize", onReposition);
    window.addEventListener("scroll", onReposition, true);
    window.addEventListener("animationend", onReposition, true);
    return () => {
      document.removeEventListener("pointerdown", onPointerDown);
      window.removeEventListener("resize", onReposition);
      window.removeEventListener("scroll", onReposition, true);
      window.removeEventListener("animationend", onReposition, true);
    };
  }, [open, selectedIndex, align, options.length]);

  useEffect(() => {
    if (!open || activeIndex < 0) return;
    const item = listRef.current?.children[activeIndex] as
      HTMLElement | undefined;
    item?.scrollIntoView({ block: "nearest" });
  }, [open, activeIndex]);

  const choose = (next: string) => {
    if (value === undefined) setInternal(next);
    setOpen(false);
    if (next !== current) onChange?.(next);
  };

  const handleKeyDown = (event: KeyboardEvent<HTMLButtonElement>) => {
    if (event.currentTarget.matches(":disabled") || !options.length) return;
    if (event.key === "Escape") {
      if (open) {
        event.preventDefault();
        event.stopPropagation();
        setOpen(false);
      }
      return;
    }
    if (event.key === "ArrowDown") {
      event.preventDefault();
      if (!open) {
        setOpen(true);
        setActiveIndex(selectedIndex);
      } else {
        setActiveIndex((i) => (i + 1) % options.length);
      }
      return;
    }
    if (event.key === "ArrowUp") {
      event.preventDefault();
      if (!open) {
        setOpen(true);
        setActiveIndex(selectedIndex);
      } else {
        setActiveIndex((i) => (i - 1 + options.length) % options.length);
      }
      return;
    }
    if (event.key === "Home" && open) {
      event.preventDefault();
      setActiveIndex(0);
      return;
    }
    if (event.key === "End" && open) {
      event.preventDefault();
      setActiveIndex(options.length - 1);
      return;
    }
    if ((event.key === "Enter" || event.key === " ") && open) {
      event.preventDefault();
      const target = options[activeIndex] ?? selected;
      if (target) choose(target.value);
    }
  };

  return (
    <div
      ref={rootRef}
      className={`select-menu ${variant}${open ? " open" : ""}${align === "right" ? " align-right" : ""}`}
    >
      {name && <input type="hidden" name={name} value={current} />}
      <button
        ref={triggerRef}
        type="button"
        className="select-trigger"
        aria-label={ariaLabel}
        aria-haspopup="listbox"
        aria-expanded={open}
        onClick={(e) => {
          if (e.currentTarget.matches(":disabled")) return;
          setOpen((v) => !v);
        }}
        onKeyDown={handleKeyDown}
      >
        {selected?.icon && (
          <span className="select-item-icon">{selected.icon}</span>
        )}
        <span className="select-label">{selected?.label ?? ""}</span>
        <ChevronDown size={15} className="select-chevron" />
      </button>
      {open && (
        <div
          ref={listRef}
          popover="manual"
          className={`select-popover ${variant}`}
          role="listbox"
          aria-label={ariaLabel}
        >
          {options.map((option, index) => {
            const isSelected = option.value === current;
            const isActive = index === activeIndex;
            return (
              <button
                key={option.value}
                type="button"
                role="option"
                aria-selected={isSelected}
                className={`select-option${isSelected ? " selected" : ""}${isActive ? " active" : ""}`}
                onMouseEnter={() => setActiveIndex(index)}
                onClick={() => choose(option.value)}
              >
                {option.icon && (
                  <span className="select-item-icon">{option.icon}</span>
                )}
                <span className="select-option-label">{option.label}</span>
                {isSelected && <Check size={14} className="select-check" />}
              </button>
            );
          })}
        </div>
      )}
    </div>
  );
}
export function Empty({ title }: { title: string }) {
  return (
    <div className="empty">
      <span className="empty-icon">
        <Inbox size={24} />
      </span>
      <h3>{title}</h3>
    </div>
  );
}
// Mark the field a modal should focus when it opens with `data-autofocus`. React's autoFocus
// runs before showModal() and is lost, so the browser would focus the close button instead.
export function Modal({
  title,
  description,
  children,
  close,
  wide = false,
}: {
  title: string;
  description?: ReactNode;
  children: ReactNode;
  close: () => void;
  wide?: boolean;
}) {
  const ref = useRef<HTMLDialogElement>(null);
  useEffect(() => {
    const dialog = ref.current;
    dialog?.showModal();
    dialog?.querySelector<HTMLElement>("[data-autofocus]")?.focus();
    return () => dialog?.close();
  }, []);
  return (
    <dialog
      ref={ref}
      className={wide ? "modal wide" : "modal"}
      onCancel={(e) => {
        // React also delivers a nested dialog's cancel here; close only the one Esc targeted.
        e.stopPropagation();
        if (e.target === ref.current) close();
      }}
      aria-label={title}
      onClick={(e) => {
        if (e.target === ref.current) {
          const b = ref.current.getBoundingClientRect();
          if (
            e.clientX < b.left ||
            e.clientX > b.right ||
            e.clientY < b.top ||
            e.clientY > b.bottom
          )
            close();
        }
      }}
    >
      <header className="modal-header">
        <div>
          <h2>{title}</h2>
          {description && <p>{description}</p>}
        </div>
        <button className="icon-button" aria-label="关闭" onClick={close}>
          <X size={18} />
        </button>
      </header>
      <div className="modal-body">{children}</div>
    </dialog>
  );
}
export function Form({
  submit,
  children,
  label = "保存",
  cancel,
}: {
  submit: (form: FormData) => Promise<void>;
  children?: ReactNode;
  label?: string;
  cancel?: () => void;
}) {
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  async function handle(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (busy) return;
    const form = new FormData(event.currentTarget);
    setBusy(true);
    setError("");
    try {
      await submit(form);
    } catch (error) {
      setError((error as Error).message);
    } finally {
      setBusy(false);
    }
  }
  return (
    <form onSubmit={handle}>
      <fieldset disabled={busy}>
        {children}
        <ErrorBox>{error}</ErrorBox>
        <div className="form-actions">
          {cancel && (
            <button type="button" className="button secondary" onClick={cancel}>
              取消
            </button>
          )}
          <button className="button primary" type="submit">
            {busy && <LoaderCircle size={16} className="spin" />}
            {busy ? "处理中…" : label}
          </button>
        </div>
      </fieldset>
    </form>
  );
}
// The Clipboard API is missing on plain-HTTP origins and can be blocked inside frames. The
// fallback copies from a hidden textarea next to the button, because nodes outside an open
// modal dialog are inert and cannot be selected.
async function copyText(value: string, anchor: HTMLElement) {
  try {
    await navigator.clipboard.writeText(value);
    return;
  } catch {
    const area = document.createElement("textarea");
    area.value = value;
    area.readOnly = true;
    area.className = "copy-buffer";
    anchor.after(area);
    area.focus();
    area.select();
    const copied = document.execCommand("copy");
    area.remove();
    anchor.focus();
    if (!copied) throw new Error("copy failed");
  }
}
export function CopyButton({
  value,
  label = "复制",
}: {
  value: string;
  label?: string;
}) {
  const [state, setState] = useState<"idle" | "copied" | "failed">("idle");
  useEffect(() => {
    if (state !== "copied") return;
    const timer = setTimeout(() => setState("idle"), 2000);
    return () => clearTimeout(timer);
  }, [state]);
  return (
    <button
      type="button"
      className="button secondary small"
      onClick={(e) =>
        copyText(value, e.currentTarget).then(
          () => setState("copied"),
          () => setState("failed"),
        )
      }
    >
      {state === "copied" ? <Check size={15} /> : <Copy size={15} />}
      {state === "copied"
        ? "已复制"
        : state === "failed"
          ? "请手动复制"
          : label}
    </button>
  );
}
interface ConfirmRequest {
  title: string;
  action: string;
}
// An in-page replacement for window.confirm, which sandboxed frames can block silently.
// Render `dialog` outside any <fieldset> that is disabled while the question is open.
export function useConfirm() {
  const [request, setRequest] = useState<
    ConfirmRequest & { answer: (ok: boolean) => void }
  >();
  const confirm = (next: ConfirmRequest) =>
    new Promise<boolean>((resolve) =>
      setRequest({
        ...next,
        answer: (ok) => {
          setRequest(undefined);
          resolve(ok);
        },
      }),
    );
  const dialog = request && (
    <Modal title={request.title} close={() => request.answer(false)}>
      <div className="form-actions confirm-actions">
        <button
          type="button"
          className="button secondary"
          data-autofocus
          onClick={() => request.answer(false)}
        >
          取消
        </button>
        <button
          type="button"
          className="button danger-solid"
          onClick={() => request.answer(true)}
        >
          {request.action}
        </button>
      </div>
    </Modal>
  );
  return [dialog, confirm] as const;
}
const statusLabels: Record<string, string> = {
  online: "连接成功",
  failed: "连接失败",
  unknown: "未检测",
};
const outcomeLabels: Record<string, string> = {
  success: "成功",
  failed: "失败",
  denied: "已拒绝",
  started: "已开始",
};
// Device connection status by default; audit results with `outcome`.
export function Status({
  value,
  outcome = false,
}: {
  value: string;
  outcome?: boolean;
}) {
  return (
    <span className={`status ${value}`}>
      <i />
      {(outcome ? outcomeLabels : statusLabels)[value] ?? value}
    </span>
  );
}
