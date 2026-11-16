import { useEffect, useState } from "react";
import {
  api,
  ErrorBox,
  Form,
  Loading,
  type User,
  type PublicConfig,
  useResource,
  roleNames,
} from "./common";

export interface EmailAction {
  action: "verify" | "reset" | "invite";
  token: string;
}

export function MailNotice() {
  const { data } = useResource<PublicConfig>("/public-config");
  return data?.mailMode === "local" || data?.mailMode === "disabled" ? (
    <div className="warning-box">未配置邮件服务，邮件不会发出。</div>
  ) : null;
}

export function AccountPanel({
  user,
  action,
  verificationRequired,
  finished,
  cancel,
}: {
  user: User | null;
  action: EmailAction | null;
  verificationRequired: boolean;
  finished: (user: User | null, completeAction?: boolean) => void;
  cancel: () => void;
}) {
  const [mode, setMode] = useState<
    "login" | "register" | "forgot-password" | "verification"
  >("login");
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");
  const [invite, setInvite] = useState<{
    team_name: string;
    role: string;
    email: string;
  }>();
  const canAccess = user && (!verificationRequired || user.email_verified);
  useEffect(() => {
    let alive = true;
    setError("");
    setInvite(undefined);
    if (action) setMessage("");
    if (action?.action === "invite" && canAccess)
      api<{ team_name: string; role: string; email: string }>(
        "/invitations/inspect",
        "POST",
        { token: action.token },
      )
        .then((data) => {
          if (alive) setInvite(data);
        })
        .catch((error) => {
          if (alive) setError(error.message);
        });
    return () => {
      alive = false;
    };
  }, [action, canAccess]);
  const logout = async () => {
    await api("/auth/logout", "POST");
    finished(null);
  };
  const switchMode = (value: typeof mode) => {
    setMode(value);
    setMessage("");
    setError("");
  };
  const setPassword = action?.action === "verify" || action?.action === "reset";
  const pendingVerification = user && !canAccess && !setPassword;
  const tabs = mode === "login" || mode === "register";
  const joining = action?.action === "invite" && canAccess;
  // The 登录/注册 tabs already name the form, so its heading is for screen readers only.
  const tabsShown = tabs && !setPassword && !joining && !pendingVerification;
  return (
    <>
      <h2 className={tabsShown ? "sr-only" : undefined}>
        {setPassword
          ? action.action === "verify"
            ? "验证邮箱并设置密码"
            : "设置新密码"
          : joining
            ? "加入团队"
            : pendingVerification
              ? "请先验证邮箱"
              : mode === "register"
                ? "创建账号"
                : mode === "forgot-password"
                  ? "找回密码"
                  : mode === "verification"
                    ? "重新发送验证邮件"
                    : "登录"}
      </h2>
      {(pendingVerification ||
        (!setPassword && !tabs) ||
        (mode === "register" && verificationRequired)) && <MailNotice />}
      {message && (
        <div className="info-box" role="status">
          {message}
        </div>
      )}
      <ErrorBox>{error}</ErrorBox>
      {setPassword ? (
        <>
          <Form
            key={action.token}
            label={action.action === "verify" ? "验证并登录" : "重置密码"}
            submit={async (form) => {
              if (form.get("password") !== form.get("confirm"))
                throw new Error("两次密码不一致");
              const result = await api<User>(`/auth/${action.action}`, "POST", {
                token: action.token,
                password: form.get("password"),
              });
              if (action.action === "verify") finished(result, true);
              else {
                setMessage("密码已重置，请重新登录。");
                setMode("login");
                finished(null, true);
              }
            }}
          >
            <label>
              新密码
              <input
                name="password"
                type="password"
                minLength={12}
                maxLength={128}
                autoComplete="new-password"
                placeholder="至少 12 位"
                required
              />
            </label>
            <label>
              确认新密码
              <input
                name="confirm"
                type="password"
                minLength={12}
                maxLength={128}
                autoComplete="new-password"
                required
              />
            </label>
          </Form>
          <div className="account-links">
            <button
              className="text-button"
              onClick={() => {
                cancel();
                switchMode(
                  action.action === "verify"
                    ? "verification"
                    : "forgot-password",
                );
              }}
            >
              链接无效？重新申请
            </button>
          </div>
        </>
      ) : joining ? (
        <>
          {!invite && !error && <Loading />}
          {invite && (
            <>
              <p className="auth-note">
                <strong>{invite.team_name}</strong> 邀请你以
                {roleNames[invite.role]}身份加入。
              </p>
              <Form
                label="加入团队"
                submit={async () => {
                  await api("/invitations/accept", "POST", {
                    token: action.token,
                  });
                  finished(user, true);
                }}
              />
            </>
          )}
          <div className="account-links">
            <button className="text-button" onClick={cancel}>
              暂不加入
            </button>
            <button
              className="text-button"
              onClick={() => logout().catch((e) => setError(e.message))}
            >
              切换账号
            </button>
          </div>
        </>
      ) : pendingVerification ? (
        <>
          <p className="auth-note">{user.email} 尚未验证。</p>
          <Form
            label="发送验证邮件"
            submit={async () => {
              const result = await api<{ message: string }>(
                "/auth/verification",
                "POST",
                { email: user.email },
              );
              setMessage(result.message);
            }}
          />
          <div className="account-links">
            <button
              className="text-button"
              onClick={() =>
                api<User>("/me")
                  .then((next) => finished(next))
                  .catch((e) => setError(e.message))
              }
            >
              我已验证，刷新状态
            </button>
            <button
              className="text-button"
              onClick={() => logout().catch((e) => setError(e.message))}
            >
              退出登录
            </button>
          </div>
        </>
      ) : (
        <>
          {action?.action === "invite" && (
            <div className="info-box">请使用收到邀请的邮箱登录或注册。</div>
          )}
          {tabsShown && (
            <div className="auth-tabs">
              <button
                className={mode === "login" ? "active" : ""}
                onClick={() => switchMode("login")}
              >
                登录
              </button>
              <button
                className={mode === "register" ? "active" : ""}
                onClick={() => switchMode("register")}
              >
                注册
              </button>
            </div>
          )}
          {mode === "register" && verificationRequired && (
            <p className="auth-note">注册后，请通过邮件中的链接设置密码。</p>
          )}
          <Form
            key={mode}
            label={
              mode === "login"
                ? "登录"
                : mode === "forgot-password"
                  ? "发送重置邮件"
                  : mode === "register" && !verificationRequired
                    ? "注册"
                    : "发送验证邮件"
            }
            submit={async (form) => {
              if (mode === "login")
                finished(
                  await api<User>(
                    "/auth/login",
                    "POST",
                    Object.fromEntries(form),
                  ),
                );
              else if (mode === "register" && !verificationRequired)
                finished(
                  await api<User>(
                    "/auth/register",
                    "POST",
                    Object.fromEntries(form),
                  ),
                );
              else {
                const result = await api<{ message: string }>(
                  `/auth/${mode}`,
                  "POST",
                  Object.fromEntries(form),
                );
                setMessage(result.message);
              }
            }}
          >
            {mode === "register" && (
              <label>
                姓名
                <input
                  name="name"
                  maxLength={80}
                  autoComplete="name"
                  required
                />
              </label>
            )}
            <label>
              邮箱
              <input
                name="email"
                type="email"
                placeholder="you@company.com"
                autoComplete="email"
                required
              />
            </label>
            {(mode === "login" ||
              (mode === "register" && !verificationRequired)) && (
              <label>
                密码
                <input
                  name="password"
                  type="password"
                  minLength={mode === "register" ? 12 : undefined}
                  maxLength={128}
                  autoComplete={
                    mode === "register" ? "new-password" : "current-password"
                  }
                  placeholder={mode === "register" ? "至少 12 位" : undefined}
                  required
                />
              </label>
            )}
          </Form>
          <div className="account-links">
            {tabs ? (
              <button
                className="text-button"
                onClick={() => switchMode("forgot-password")}
              >
                忘记密码？
              </button>
            ) : (
              <button
                className="text-button"
                onClick={() => switchMode("login")}
              >
                返回登录
              </button>
            )}
            {verificationRequired && mode !== "verification" && (
              <button
                className="text-button"
                onClick={() => switchMode("verification")}
              >
                重新发送验证邮件
              </button>
            )}
          </div>
        </>
      )}
    </>
  );
}
