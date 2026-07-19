import {
  DETECTION_LAYERS,
  clampScore,
  formatDateTime,
  getExplanationGroups,
  getLayerFindingCount,
  getRecommendedActions,
  getRiskCopy,
  getRiskTone,
} from "../reportUtils";
import {
  ConsoleIcon,
  SectionHeading,
  ShieldIcon,
} from "./ConsolePrimitives";

function RiskGauge({ score, label }) {
  const safeScore = clampScore(score);
  const tone = getRiskTone(label, safeScore);
  const angle = Math.PI - (safeScore / 100) * Math.PI;
  const markerX = 100 + 78 * Math.cos(angle);
  const markerY = 100 - 78 * Math.sin(angle);

  return (
    <div className={`risk-gauge gauge-${tone}`}>
      <svg
        aria-hidden="true"
        focusable="false"
        viewBox="0 0 200 116"
      >
        <path
          className="gauge-track"
          d="M20 100 A80 80 0 0 1 180 100"
          pathLength="100"
        />
        <path
          className="gauge-progress"
          d="M20 100 A80 80 0 0 1 180 100"
          pathLength="100"
          strokeDasharray={`${safeScore} 100`}
        />
        <circle className="gauge-marker" cx={markerX} cy={markerY} r="5" />
      </svg>
      <div className="gauge-value">
        <strong>{safeScore}</strong>
        <span>/100</span>
      </div>
      <span className="gauge-caption">RISK SCORE</span>
    </div>
  );
}

function LayerScore({ layer, report }) {
  const score = clampScore(report[layer.scoreKey]);
  const tone = getRiskTone("", score);
  const findingCount = getLayerFindingCount(report, layer.key);

  return (
    <div className="layer-row">
      <div className="layer-row-heading">
        <div>
          <span className="layer-code">{layer.shortName}</span>
          <strong>{layer.name}</strong>
        </div>
        <div className="layer-score">
          <strong>{score}</strong>
          <span>/100</span>
        </div>
      </div>
      <div
        aria-label={`${layer.name} score ${score} out of 100`}
        aria-valuemax="100"
        aria-valuemin="0"
        aria-valuenow={score}
        className="score-track"
        role="progressbar"
      >
        <span
          className={`score-fill score-${tone}`}
          style={{ width: `${score}%` }}
        />
      </div>
      <div className="layer-row-meta">
        <span>{layer.weight}% base weight</span>
        {findingCount !== null && (
          <span>
            {findingCount} {findingCount === 1 ? "finding" : "findings"}
          </span>
        )}
      </div>
    </div>
  );
}

function Findings({ report }) {
  const groups = getExplanationGroups(report);

  return (
    <section className="report-subpanel findings-panel" aria-labelledby="findings-title">
      <div className="subpanel-heading">
        <div>
          <p className="technical-label">RETURNED BY THE API</p>
          <h3 id="findings-title">Detection Explanation</h3>
        </div>
        <span>
          {groups.reduce((total, group) => total + group.items.length, 0)} returned
        </span>
      </div>

      <div className="finding-groups">
        {groups.map((group) => (
          <section className={`finding-group finding-${group.key}`} key={group.key}>
            <div className="finding-group-heading">
              <span>{group.name}</span>
              {group.key !== "all" && (
                <small>{group.items.length} returned</small>
              )}
            </div>

            {group.terms.length > 0 && (
              <div className="term-list" aria-label="Suspicious model terms">
                {group.terms.map((term) => (
                  <span key={term}>{term}</span>
                ))}
              </div>
            )}

            {group.items.length > 0 ? (
              <ul>
                {group.items.map((item, index) => (
                  <li key={`${group.key}-${item}-${index}`}>{item}</li>
                ))}
              </ul>
            ) : (
              <p className="no-findings">
                No major suspicious indicators were returned.
              </p>
            )}
          </section>
        ))}
      </div>
    </section>
  );
}

function EmptyReport() {
  return (
    <div className="console-panel report-empty-state">
      <span className="empty-shield">
        <ShieldIcon />
      </span>
      <p className="technical-label">NO SCAN LOADED</p>
      <h3>Threat report awaiting input</h3>
      <p>
        Enter supported email fields or parse a raw message, then run the analysis
        to generate an explainable four-layer report.
      </p>
    </div>
  );
}

export default function ThreatReport({ report, metadata, email }) {
  if (!report) {
    return (
      <section className="workspace-section report-section" aria-labelledby="report-heading">
        <SectionHeading
          id="report-heading"
          note="Awaiting input"
          number="02"
          title="THREAT REPORT"
        />
        <EmptyReport />
      </section>
    );
  }

  const score = clampScore(report.risk_score);
  const tone = getRiskTone(report.label, score);
  const riskCopy = getRiskCopy(report.label, score);
  const actions = getRecommendedActions(report.label, score);
  const formattedDate = formatDateTime(metadata?.created_at);

  return (
    <section className="workspace-section report-section" aria-labelledby="report-heading">
      <SectionHeading
        id="report-heading"
        note={metadata?.source === "history" ? "Saved scan selected" : "Layered detection result"}
        number="02"
        title="THREAT REPORT"
      />

      <div className="report-content">
        <section className={`console-panel report-summary summary-${tone}`}>
          <RiskGauge label={report.label} score={score} />

          <div className="verdict-block">
            <span className={`risk-badge badge-${tone}`}>
              <span aria-hidden="true" />
              {report.label}
            </span>
            <h3>{riskCopy.verdict}</h3>
            <p>{riskCopy.message}</p>

            {(email?.subject || email?.sender) && (
              <dl className="report-email-context">
                {email.subject && (
                  <div>
                    <dt>Subject</dt>
                    <dd>{email.subject}</dd>
                  </div>
                )}
                {email.sender && (
                  <div>
                    <dt>Sender</dt>
                    <dd>{email.sender}</dd>
                  </div>
                )}
              </dl>
            )}

            {(formattedDate || metadata?.id) && (
              <div className="report-metadata">
                {formattedDate && (
                  <span>
                    <ConsoleIcon name="clock" />
                    {formattedDate}
                  </span>
                )}
                {metadata?.id && <span>History record #{metadata.id}</span>}
              </div>
            )}
          </div>
        </section>

        <div className="report-detail-grid">
          <section className="report-subpanel layers-panel" aria-labelledby="layers-title">
            <div className="subpanel-heading">
              <div>
                <p className="technical-label">FOUR REAL DETECTION LAYERS</p>
                <h3 id="layers-title">Layered Scores</h3>
              </div>
              <span>0–100</span>
            </div>

            <div className="layer-list">
              {DETECTION_LAYERS.map((layer) => (
                <LayerScore key={layer.key} layer={layer} report={report} />
              ))}
            </div>
          </section>

          <section className="report-subpanel actions-panel" aria-labelledby="actions-title">
            <div className="subpanel-heading">
              <div>
                <p className="technical-label">GENERAL SAFETY GUIDANCE</p>
                <h3 id="actions-title">Recommended Actions</h3>
              </div>
            </div>

            <ul>
              {actions.map((action) => (
                <li key={action}>
                  <ConsoleIcon name="check" />
                  <span>{action}</span>
                </li>
              ))}
            </ul>
          </section>
        </div>

        <Findings report={report} />

        {metadata?.source === "history" && !report.explanation && (
          <p className="history-report-note">
            This saved record contains the scores and reason strings retained by the
            history API. Grouped model terms are only available in the immediate scan
            response.
          </p>
        )}
      </div>
    </section>
  );
}
