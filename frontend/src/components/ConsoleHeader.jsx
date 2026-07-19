import { ConsoleIcon, ShieldIcon } from "./ConsolePrimitives";

function HeaderCounter({ icon, label, value, tone = "neutral" }) {
  return (
    <div className={`header-counter counter-${tone}`}>
      <ConsoleIcon name={icon} />
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

export default function ConsoleHeader({ counts, username, onLogout }) {
  return (
    <header className="console-header">
      <div className="console-header-inner">
        <a className="console-brand" href="#console" aria-label="ThreatLens console">
          <span className="brand-shield">
            <ShieldIcon />
            <span className="status-dot" />
          </span>
          <span className="console-brand-copy">
            <span className="console-brand-title">
              THREATLENS <b aria-hidden="true">›</b> SOC CONSOLE
            </span>
            <span className="console-brand-subtitle">
              Explainable email threat detection · 4-layer analysis
            </span>
          </span>
        </a>

        <div className="header-counters" aria-label="Scan history summary">
          <HeaderCounter
            icon="database"
            label="Scans"
            value={counts.total}
          />
          <HeaderCounter
            icon="pulse"
            label="High"
            tone="high"
            value={counts.high}
          />
          <HeaderCounter
            icon="pulse"
            label="Medium"
            tone="medium"
            value={counts.medium}
          />
          <HeaderCounter
            icon="check"
            label="Low"
            tone="low"
            value={counts.low}
          />
        </div>

        <nav className="header-actions" aria-label="Console actions">
          <a className="header-link" href="#about">
            <ConsoleIcon name="info" />
            About
          </a>
          {username && (
            <span className="username-badge" title={username}>
              {username}
            </span>
          )}
          <button className="header-link" onClick={onLogout} type="button">
            <ConsoleIcon name="logout" />
            Logout
          </button>
        </nav>
      </div>
    </header>
  );
}
