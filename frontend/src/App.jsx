import { useState } from "react";
import {
  TOKEN_STORAGE_KEY,
  loginUser,
  registerUser,
  scanEmail,
} from "./api";
import "./App.css";

const SAMPLES = {
  clean: {
    sender: "updates@stripe.com",
    reply_to: "",
    subject: "Monthly report",
    body: "Your monthly report is ready. View it here: https://dashboard.stripe.com/reports/monthly",
  },
  malicious: {
    sender: "support@paypa1-secure.com",
    reply_to: "attacker@gmail.com",
    subject: "URGENT verify your account",
    body: "Your account has been compromised. Verify your information immediately here: http://192.168.4.21/login",
  },
};

const EMPTY_EMAIL = {
  sender: "",
  reply_to: "",
  subject: "",
  body: "",
};

const EMPTY_AUTH = {
  username: "",
  password: "",
};

function getErrorMessage(error, fallback) {
  return error.response?.data?.detail ?? fallback;
}

function getRiskClass(label) {
  if (label === "High Risk") {
    return "risk-high";
  }

  if (label === "Medium Risk") {
    return "risk-medium";
  }

  return "risk-low";
}

export default function App() {
  const [token, setToken] = useState(() => localStorage.getItem(TOKEN_STORAGE_KEY));
  const [username, setUsername] = useState(() => localStorage.getItem("threatlens_user") ?? "");
  const [authMode, setAuthMode] = useState("login");
  const [authForm, setAuthForm] = useState(EMPTY_AUTH);
  const [form, setForm] = useState(EMPTY_EMAIL);
  const [report, setReport] = useState(null);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");

  const isAuthenticated = Boolean(token);

  const updateAuthField = (field, value) => {
    setAuthForm((current) => ({ ...current, [field]: value }));
  };

  const updateEmailField = (field, value) => {
    setForm((current) => ({ ...current, [field]: value }));
  };

  const saveSession = (nextToken, nextUsername) => {
    localStorage.setItem(TOKEN_STORAGE_KEY, nextToken);
    localStorage.setItem("threatlens_user", nextUsername);
    setToken(nextToken);
    setUsername(nextUsername);
    setMessage("");
  };

  const handleLogin = async (event) => {
    event.preventDefault();
    setBusy(true);
    setMessage("");

    try {
      const data = await loginUser(authForm);
      saveSession(data.access_token, authForm.username.trim().toLowerCase());
      setAuthForm(EMPTY_AUTH);
    } catch (error) {
      setMessage(getErrorMessage(error, "Login failed"));
    } finally {
      setBusy(false);
    }
  };

  const handleRegister = async (event) => {
    event.preventDefault();
    setBusy(true);
    setMessage("");

    try {
      await registerUser(authForm);
      const data = await loginUser(authForm);
      saveSession(data.access_token, authForm.username.trim().toLowerCase());
      setAuthForm(EMPTY_AUTH);
    } catch (error) {
      setMessage(getErrorMessage(error, "Registration failed"));
    } finally {
      setBusy(false);
    }
  };

  const logout = () => {
    localStorage.removeItem(TOKEN_STORAGE_KEY);
    localStorage.removeItem("threatlens_user");
    setToken(null);
    setUsername("");
    setReport(null);
    setMessage("");
  };

  const submitScan = async (event) => {
    event.preventDefault();
    setBusy(true);
    setMessage("");

    try {
      const payload = {
        sender: form.sender,
        subject: form.subject,
        body: form.body,
        reply_to: form.reply_to || null,
      };

      setReport(await scanEmail(payload, token));
    } catch (error) {
      setMessage(getErrorMessage(error, "Scan failed"));

      if (error.response?.status === 401) {
        logout();
      }
    } finally {
      setBusy(false);
    }
  };

  const loadSample = (sample) => {
    setForm(SAMPLES[sample]);
    setReport(null);
    setMessage("");
  };

  if (!isAuthenticated) {
    const isLogin = authMode === "login";

    return (
      <main className="auth-shell">
        <section className="auth-panel">
          <div className="brand-block">
            <p className="eyebrow">ThreatLens</p>
            <h1>{isLogin ? "Login" : "Register"}</h1>
          </div>

          <form className="auth-form" onSubmit={isLogin ? handleLogin : handleRegister}>
            <label>
              Username
              <input
                autoComplete="username"
                minLength={3}
                onChange={(event) => updateAuthField("username", event.target.value)}
                required
                type="text"
                value={authForm.username}
              />
            </label>

            <label>
              Password
              <input
                autoComplete={isLogin ? "current-password" : "new-password"}
                minLength={8}
                onChange={(event) => updateAuthField("password", event.target.value)}
                required
                type="password"
                value={authForm.password}
              />
            </label>

            {message && <p className="form-message">{message}</p>}

            <button className="primary-button" disabled={busy} type="submit">
              {busy ? "Working..." : isLogin ? "Login" : "Create account"}
            </button>
          </form>

          <button
            className="link-button"
            onClick={() => {
              setAuthMode(isLogin ? "register" : "login");
              setMessage("");
            }}
            type="button"
          >
            {isLogin ? "Create an account" : "Use existing account"}
          </button>
        </section>
      </main>
    );
  }

  return (
    <main className="dashboard-shell">
      <header className="topbar">
        <div>
          <p className="eyebrow">ThreatLens</p>
          <h1>Email scan dashboard</h1>
        </div>
        <div className="session-actions">
          <span>{username}</span>
          <button className="secondary-button" onClick={logout} type="button">
            Logout
          </button>
        </div>
      </header>

      <section className="dashboard-grid">
        <div className="scan-panel">
          <div className="sample-actions">
            <button className="secondary-button" onClick={() => loadSample("clean")} type="button">
              Load clean sample
            </button>
            <button className="secondary-button" onClick={() => loadSample("malicious")} type="button">
              Load phishing sample
            </button>
          </div>

          <form className="scan-form" onSubmit={submitScan}>
            <label>
              From
              <input
                onChange={(event) => updateEmailField("sender", event.target.value)}
                required
                type="email"
                value={form.sender}
              />
            </label>

            <label>
              Reply-To
              <input
                onChange={(event) => updateEmailField("reply_to", event.target.value)}
                type="email"
                value={form.reply_to}
              />
            </label>

            <label>
              Subject
              <input
                onChange={(event) => updateEmailField("subject", event.target.value)}
                required
                type="text"
                value={form.subject}
              />
            </label>

            <label>
              Email body
              <textarea
                onChange={(event) => updateEmailField("body", event.target.value)}
                required
                rows={10}
                value={form.body}
              />
            </label>

            {message && <p className="form-message">{message}</p>}

            <button className="primary-button" disabled={busy} type="submit">
              {busy ? "Scanning..." : "Scan email"}
            </button>
          </form>
        </div>

        <aside className="result-panel">
          {report ? (
            <>
              <div className={`risk-summary ${getRiskClass(report.label)}`}>
                <p className="eyebrow">Risk</p>
                <strong>{report.risk_score}/100</strong>
                <span>{report.label}</span>
              </div>

              <div className="score-grid">
                <div>
                  <span>ML</span>
                  <strong>{report.ml_score}</strong>
                </div>
                <div>
                  <span>NLP</span>
                  <strong>{report.nlp_score}</strong>
                </div>
                <div>
                  <span>URL</span>
                  <strong>{report.url_score}</strong>
                </div>
                <div>
                  <span>Metadata</span>
                  <strong>{report.metadata_score}</strong>
                </div>
              </div>

              <div className="reasons-block">
                <h2>Reasons</h2>
                <ul>
                  {report.reasons.map((reason, index) => (
                    <li key={`${reason}-${index}`}>{reason}</li>
                  ))}
                </ul>
              </div>
            </>
          ) : (
            <div className="empty-state">
              <p className="eyebrow">Result</p>
              <h2>No scan yet</h2>
            </div>
          )}
        </aside>
      </section>
    </main>
  );
}
