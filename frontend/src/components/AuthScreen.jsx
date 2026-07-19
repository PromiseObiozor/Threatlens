import {
  ConsoleIcon,
  LoadingSpinner,
  ShieldIcon,
} from "./ConsolePrimitives";

export default function AuthScreen({
  mode,
  form,
  busy,
  message,
  onChange,
  onSubmit,
  onToggleMode,
}) {
  const isLogin = mode === "login";

  return (
    <main className="auth-shell">
      <section className="auth-panel" aria-labelledby="auth-title">
        <div className="auth-brand">
          <span className="brand-shield">
            <ShieldIcon />
            <span className="status-dot" />
          </span>
          <div>
            <p className="brand-name">THREATLENS</p>
            <p className="brand-console">SOC CONSOLE</p>
          </div>
        </div>

        <div className="auth-heading">
          <p className="technical-label">SECURE PROJECT ACCESS</p>
          <h1 id="auth-title">{isLogin ? "Welcome back" : "Create an account"}</h1>
          <p>
            {isLogin
              ? "Sign in to analyse messages and review your saved scan history."
              : "Register to use the four-layer email threat analysis console."}
          </p>
        </div>

        <form className="auth-form" onSubmit={onSubmit}>
          <label htmlFor="auth-username">
            Username <span className="required-mark">*</span>
          </label>
          <input
            autoComplete="username"
            disabled={busy}
            id="auth-username"
            minLength={3}
            onChange={(event) => onChange("username", event.target.value)}
            required
            type="text"
            value={form.username}
          />

          <label htmlFor="auth-password">
            Password <span className="required-mark">*</span>
          </label>
          <input
            autoComplete={isLogin ? "current-password" : "new-password"}
            disabled={busy}
            id="auth-password"
            minLength={8}
            onChange={(event) => onChange("password", event.target.value)}
            required
            type="password"
            value={form.password}
          />

          {!isLogin && (
            <p className="field-help">Use at least 8 characters.</p>
          )}

          {message && (
            <p className="form-message" role="alert">
              {message}
            </p>
          )}

          <button className="primary-button auth-submit" disabled={busy} type="submit">
            {busy ? (
              <>
                <LoadingSpinner />
                {isLogin ? "Signing in..." : "Creating account..."}
              </>
            ) : (
              <>
                <ConsoleIcon name="scan" />
                {isLogin ? "Sign in to console" : "Create account"}
              </>
            )}
          </button>
        </form>

        <div className="auth-switch">
          <span>{isLogin ? "New to ThreatLens?" : "Already registered?"}</span>
          <button disabled={busy} onClick={onToggleMode} type="button">
            {isLogin ? "Create an account" : "Use existing account"}
          </button>
        </div>

        <a className="auth-about-link" href="#about">
          <ConsoleIcon name="info" />
          Read the project methodology
        </a>

        <p className="auth-footnote">
          Final-year cybersecurity project · four explainable detection layers
        </p>
      </section>
    </main>
  );
}
