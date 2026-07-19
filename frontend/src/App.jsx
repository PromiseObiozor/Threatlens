import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  TOKEN_STORAGE_KEY,
  deleteHistoryItem,
  getHistory,
  loginUser,
  registerUser,
  scanEmail,
} from "./api";
import AboutPage from "./components/AboutPage";
import AuthScreen from "./components/AuthScreen";
import ConsoleHeader from "./components/ConsoleHeader";
import EmailInputPanel from "./components/EmailInputPanel";
import HistoryPanel from "./components/HistoryPanel";
import ThreatReport from "./components/ThreatReport";
import { getParserStatus, parseEmailText } from "./emailParser";
import { getHistoryCounts } from "./reportUtils";
import "./App.css";

const SAMPLES = {
  clean: {
    sender: "updates@stripe.com",
    reply_to: "",
    subject: "Monthly report",
    body: "Your monthly report is ready. View it here: https://dashboard.stripe.com/reports/monthly",
  },
  suspicious: {
    sender: "director@project-partner.com",
    reply_to: "director@project-partner.com",
    subject: "Confidential vendor payment request",
    body: "Please process payment for the new vendor today. Keep this confidential and do not call until I confirm the invoice details.",
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
  const detail = error.response?.data?.detail;

  if (typeof detail === "string") {
    return detail;
  }

  if (Array.isArray(detail)) {
    const messages = detail
      .map((item) => item?.msg)
      .filter(Boolean);

    if (messages.length > 0) {
      return messages.join(" ");
    }
  }

  return fallback;
}

function getInitialView() {
  return window.location.hash.toLowerCase() === "#about" ? "about" : "console";
}

function validateEmail(form) {
  if (!form.sender.trim()) {
    return "Sender / From is required.";
  }

  if (!form.subject.trim()) {
    return "Subject is required.";
  }

  if (!form.body.trim()) {
    return "Email body is required.";
  }

  return "";
}

export default function App() {
  const [view, setView] = useState(getInitialView);
  const [token, setToken] = useState(() => localStorage.getItem(TOKEN_STORAGE_KEY));
  const [username, setUsername] = useState(
    () => localStorage.getItem("threatlens_user") ?? "",
  );
  const [authMode, setAuthMode] = useState("login");
  const [authForm, setAuthForm] = useState(EMPTY_AUTH);
  const [authBusy, setAuthBusy] = useState(false);
  const [authMessage, setAuthMessage] = useState("");

  const [inputMode, setInputMode] = useState("fields");
  const [form, setForm] = useState(EMPTY_EMAIL);
  const [rawEmail, setRawEmail] = useState("");
  const [parserResult, setParserResult] = useState(null);
  const [scanBusy, setScanBusy] = useState(false);
  const [scanMessage, setScanMessage] = useState("");

  const [report, setReport] = useState(null);
  const [reportMetadata, setReportMetadata] = useState(null);
  const [reportEmail, setReportEmail] = useState(null);

  const [history, setHistory] = useState([]);
  const [historyLoading, setHistoryLoading] = useState(false);
  const [historyMessage, setHistoryMessage] = useState("");
  const [deletingId, setDeletingId] = useState(null);
  const [selectedScanId, setSelectedScanId] = useState(null);
  const [announcement, setAnnouncement] = useState("");

  const sessionVersionRef = useRef(0);
  const historyRequestRef = useRef(0);
  const selectedScanIdRef = useRef(null);

  const isAuthenticated = Boolean(token);
  const counts = useMemo(() => getHistoryCounts(history), [history]);
  const parserStatus = parserResult
    ? getParserStatus(parserResult, form)
    : "";
  const parserWarning = parserResult
    ? ["sender", "reply_to", "subject", "body"].some(
        (field) => !parserResult[field]?.trim(),
      )
    : false;

  const isCurrentSession = useCallback(
    (requestVersion, requestToken) =>
      sessionVersionRef.current === requestVersion &&
      localStorage.getItem(TOKEN_STORAGE_KEY) === requestToken,
    [],
  );

  useEffect(() => {
    const handleHashChange = () => setView(getInitialView());

    window.addEventListener("hashchange", handleHashChange);

    return () => window.removeEventListener("hashchange", handleHashChange);
  }, []);

  const setCurrentScanId = useCallback((scanId) => {
    selectedScanIdRef.current = scanId;
    setSelectedScanId(scanId);
  }, []);

  const clearReport = useCallback(() => {
    setReport(null);
    setReportMetadata(null);
    setReportEmail(null);
    setCurrentScanId(null);
  }, [setCurrentScanId]);

  const resetWorkspace = useCallback(() => {
    setHistory([]);
    setHistoryLoading(false);
    setHistoryMessage("");
    setDeletingId(null);
    setScanBusy(false);
    setAuthMode("login");
    setAuthForm(EMPTY_AUTH);
    setInputMode("fields");
    setForm(EMPTY_EMAIL);
    setRawEmail("");
    setParserResult(null);
    setScanMessage("");
    setAnnouncement("");
    clearReport();
  }, [clearReport]);

  const endSession = useCallback(
    (reason = "") => {
      sessionVersionRef.current += 1;
      historyRequestRef.current += 1;
      localStorage.removeItem(TOKEN_STORAGE_KEY);
      localStorage.removeItem("threatlens_user");
      setToken(null);
      setUsername("");
      resetWorkspace();
      setAuthMessage(reason);
    },
    [resetWorkspace],
  );

  useEffect(() => {
    const handleStorage = (event) => {
      if (
        event.key !== TOKEN_STORAGE_KEY &&
        event.key !== "threatlens_user"
      ) {
        return;
      }

      const nextToken = localStorage.getItem(TOKEN_STORAGE_KEY);
      const nextUsername = localStorage.getItem("threatlens_user") ?? "";

      if (nextToken === token) {
        setUsername(nextToken ? nextUsername : "");
        return;
      }

      sessionVersionRef.current += 1;
      historyRequestRef.current += 1;
      resetWorkspace();
      setToken(nextToken);
      setUsername(nextToken ? nextUsername : "");
      setAuthMessage(
        nextToken ? "" : "You were signed out in another browser tab.",
      );
    };

    window.addEventListener("storage", handleStorage);

    return () => window.removeEventListener("storage", handleStorage);
  }, [resetWorkspace, token]);

  useEffect(() => {
    let cancelled = false;

    async function loadSavedHistory() {
      if (!token) {
        return;
      }

      const requestVersion = sessionVersionRef.current;
      const requestToken = token;
      const requestId = ++historyRequestRef.current;
      const isCurrentRequest = () =>
        !cancelled &&
        historyRequestRef.current === requestId &&
        isCurrentSession(requestVersion, requestToken);

      setHistoryLoading(true);
      setHistoryMessage("");

      try {
        const savedScans = await getHistory(requestToken);

        if (isCurrentRequest()) {
          setHistory(savedScans);
        }
      } catch (error) {
        if (!isCurrentRequest()) {
          return;
        }

        if (error.response?.status === 401) {
          endSession("Your session has expired. Please sign in again.");
        } else {
          setHistoryMessage(
            getErrorMessage(error, "Saved scans could not be loaded."),
          );
        }
      } finally {
        if (isCurrentRequest()) {
          setHistoryLoading(false);
        }
      }
    }

    loadSavedHistory();

    return () => {
      cancelled = true;
    };
  }, [endSession, isCurrentSession, token]);

  const updateAuthField = (field, value) => {
    setAuthForm((current) => ({ ...current, [field]: value }));
    setAuthMessage("");
  };

  const saveSession = (nextToken, nextUsername) => {
    sessionVersionRef.current += 1;
    historyRequestRef.current += 1;
    localStorage.setItem(TOKEN_STORAGE_KEY, nextToken);
    localStorage.setItem("threatlens_user", nextUsername);
    setHistory([]);
    setHistoryLoading(false);
    setHistoryMessage("");
    clearReport();
    setToken(nextToken);
    setUsername(nextUsername);
    setAuthMessage("");
    window.location.hash = "console";
  };

  const handleLogin = async (event) => {
    event.preventDefault();

    if (authBusy) {
      return;
    }

    setAuthBusy(true);
    setAuthMessage("");

    try {
      const data = await loginUser(authForm);
      saveSession(data.access_token, authForm.username.trim().toLowerCase());
      setAuthForm(EMPTY_AUTH);
    } catch (error) {
      setAuthMessage(getErrorMessage(error, "Login failed. Please try again."));
    } finally {
      setAuthBusy(false);
    }
  };

  const handleRegister = async (event) => {
    event.preventDefault();

    if (authBusy) {
      return;
    }

    setAuthBusy(true);
    setAuthMessage("");

    try {
      await registerUser(authForm);

      try {
        const data = await loginUser(authForm);
        saveSession(data.access_token, authForm.username.trim().toLowerCase());
        setAuthForm(EMPTY_AUTH);
      } catch {
        setAuthMode("login");
        setAuthForm((current) => ({ ...current, password: "" }));
        setAuthMessage(
          "Account created, but automatic sign-in did not complete. Please sign in.",
        );
      }
    } catch (error) {
      setAuthMessage(
        getErrorMessage(error, "Registration failed. Please try again."),
      );
    } finally {
      setAuthBusy(false);
    }
  };

  const updateEmailField = (field, value) => {
    setForm((current) => ({ ...current, [field]: value }));
    setScanMessage("");
    clearReport();
  };

  const handleParseEmail = () => {
    if (!rawEmail.trim()) {
      setParserResult(null);
      setScanMessage("Paste a full email before parsing.");
      return;
    }

    const parsedEmail = parseEmailText(rawEmail);

    setForm(parsedEmail);
    setParserResult(parsedEmail);
    setInputMode("fields");
    setScanMessage("");
    clearReport();
  };

  const loadSample = (sampleName) => {
    setForm({ ...SAMPLES[sampleName] });
    setRawEmail("");
    setParserResult(null);
    setInputMode("fields");
    setScanMessage("");
    clearReport();
  };

  const clearInput = () => {
    setForm(EMPTY_EMAIL);
    setRawEmail("");
    setParserResult(null);
    setScanMessage("");
    clearReport();
  };

  const submitScan = async (event) => {
    event.preventDefault();

    if (scanBusy) {
      return;
    }

    const validationMessage = validateEmail(form);

    if (validationMessage) {
      setScanMessage(validationMessage);
      return;
    }

    setScanBusy(true);
    setScanMessage("");
    setHistoryMessage("");
    setAnnouncement("Threat analysis in progress.");
    clearReport();

    const payload = {
      sender: form.sender.trim(),
      subject: form.subject.trim(),
      body: form.body,
      reply_to: form.reply_to.trim() || null,
    };
    const requestVersion = sessionVersionRef.current;
    const requestToken = token;

    try {
      const scanResult = await scanEmail(payload, requestToken);

      if (!isCurrentSession(requestVersion, requestToken)) {
        return;
      }

      setReport(scanResult);
      setReportEmail({ ...payload });
      setReportMetadata({ source: "fresh" });
      setCurrentScanId(null);
      setAnnouncement(
        `Analysis complete: ${scanResult.label}, score ${scanResult.risk_score} out of 100.`,
      );

      const historyRequestId = ++historyRequestRef.current;
      setHistoryLoading(true);
      try {
        const savedScans = await getHistory(requestToken);

        if (
          isCurrentSession(requestVersion, requestToken) &&
          historyRequestRef.current === historyRequestId
        ) {
          setHistory(savedScans);
        }
      } catch (historyError) {
        if (!isCurrentSession(requestVersion, requestToken)) {
          return;
        }

        if (historyError.response?.status === 401) {
          endSession("Your session has expired. Please sign in again.");
          return;
        }

        setHistoryMessage(
          getErrorMessage(
            historyError,
            "The scan completed, but history could not be refreshed.",
          ),
        );
      } finally {
        if (
          isCurrentSession(requestVersion, requestToken) &&
          historyRequestRef.current === historyRequestId
        ) {
          setHistoryLoading(false);
        }
      }
    } catch (error) {
      if (!isCurrentSession(requestVersion, requestToken)) {
        return;
      }

      if (error.response?.status === 401) {
        endSession("Your session has expired. Please sign in again.");
        return;
      }

      setScanMessage(getErrorMessage(error, "The email scan failed."));
      setAnnouncement("Threat analysis failed.");
    } finally {
      if (isCurrentSession(requestVersion, requestToken)) {
        setScanBusy(false);
      }
    }
  };

  const refreshHistory = async () => {
    if (!token || historyLoading || scanBusy || deletingId) {
      return;
    }

    const requestVersion = sessionVersionRef.current;
    const requestToken = token;
    const requestId = ++historyRequestRef.current;
    const isCurrentRequest = () =>
      historyRequestRef.current === requestId &&
      isCurrentSession(requestVersion, requestToken);

    setHistoryLoading(true);
    setHistoryMessage("");

    try {
      const savedScans = await getHistory(requestToken);

      if (isCurrentRequest()) {
        setHistory(savedScans);
      }
    } catch (error) {
      if (!isCurrentRequest()) {
        return;
      }

      if (error.response?.status === 401) {
        endSession("Your session has expired. Please sign in again.");
        return;
      }

      setHistoryMessage(
        getErrorMessage(error, "Saved scans could not be refreshed."),
      );
    } finally {
      if (isCurrentRequest()) {
        setHistoryLoading(false);
      }
    }
  };

  const selectHistoryItem = (item) => {
    if (deletingId || scanBusy) {
      return;
    }

    setReport({
      risk_score: item.risk_score,
      label: item.label,
      ml_score: item.ml_score,
      nlp_score: item.nlp_score,
      url_score: item.url_score,
      metadata_score: item.metadata_score,
      reasons: item.reasons ?? [],
    });
    setReportMetadata({
      id: item.id,
      created_at: item.created_at,
      source: "history",
    });
    setReportEmail({
      sender: item.sender,
      reply_to: item.reply_to,
      subject: item.subject,
      body: item.body_preview,
    });
    setCurrentScanId(item.id);
    setAnnouncement(
      `Saved report loaded: ${item.label}, score ${item.risk_score} out of 100.`,
    );
  };

  const removeHistoryItem = async (item) => {
    const confirmed = window.confirm(
      `Delete the saved scan for “${item.subject || "No subject"}”? This cannot be undone.`,
    );

    if (!confirmed) {
      return;
    }

    const requestVersion = sessionVersionRef.current;
    const requestToken = token;
    historyRequestRef.current += 1;
    setDeletingId(item.id);
    setHistoryLoading(false);
    setHistoryMessage("");

    try {
      await deleteHistoryItem(item.id, requestToken);

      if (!isCurrentSession(requestVersion, requestToken)) {
        return;
      }

      setHistory((current) => current.filter((entry) => entry.id !== item.id));
      setAnnouncement("Saved scan deleted.");

      if (selectedScanIdRef.current === item.id) {
        clearReport();
      }
    } catch (error) {
      if (!isCurrentSession(requestVersion, requestToken)) {
        return;
      }

      if (error.response?.status === 401) {
        endSession("Your session has expired. Please sign in again.");
        return;
      }

      setHistoryMessage(
        getErrorMessage(error, "The saved scan could not be deleted."),
      );
    } finally {
      if (isCurrentSession(requestVersion, requestToken)) {
        setDeletingId(null);
      }
    }
  };

  if (view === "about") {
    return <AboutPage isAuthenticated={isAuthenticated} />;
  }

  if (!isAuthenticated) {
    const isLogin = authMode === "login";

    return (
      <AuthScreen
        busy={authBusy}
        form={authForm}
        message={authMessage}
        mode={authMode}
        onChange={updateAuthField}
        onSubmit={isLogin ? handleLogin : handleRegister}
        onToggleMode={() => {
          setAuthMode(isLogin ? "register" : "login");
          setAuthMessage("");
        }}
      />
    );
  }

  return (
    <div className="dashboard-shell">
      <p className="sr-only" aria-live="polite" role="status">
        {announcement}
      </p>
      <ConsoleHeader
        counts={counts}
        onLogout={() => endSession()}
        username={username}
      />

      <main className="console-main">
        <h1 className="sr-only">ThreatLens email threat analysis console</h1>
        <div className="dashboard-grid">
          <EmailInputPanel
            busy={scanBusy}
            form={form}
            message={scanMessage}
            mode={inputMode}
            onClear={clearInput}
            onFieldChange={updateEmailField}
            onLoadSample={loadSample}
            onModeChange={(nextMode) => {
              setInputMode(nextMode);
              setScanMessage("");
            }}
            onParse={handleParseEmail}
            onRawEmailChange={(value) => {
              setRawEmail(value);
              setParserResult(null);
              setScanMessage("");
              clearReport();
            }}
            onSubmit={submitScan}
            parserStatus={parserStatus}
            parserWarning={parserWarning}
            rawEmail={rawEmail}
          />

          <ThreatReport
            email={reportEmail}
            metadata={reportMetadata}
            report={report}
          />

          <HistoryPanel
            deletingId={deletingId}
            history={history}
            loading={historyLoading}
            message={historyMessage}
            onDelete={removeHistoryItem}
            onRefresh={refreshHistory}
            onSelect={selectHistoryItem}
            selectedId={selectedScanId}
            interactionDisabled={Boolean(deletingId) || scanBusy}
          />
        </div>
      </main>
    </div>
  );
}
