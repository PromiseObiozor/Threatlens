import { DETECTION_LAYERS } from "../reportUtils";
import { ConsoleIcon, ShieldIcon } from "./ConsolePrimitives";

const LAYER_DETAILS = {
  ml: {
    purpose: "Classifies message content",
    detail:
      "A TF-IDF vectoriser and logistic-regression model estimate how closely the subject and body resemble the project’s spam training examples.",
  },
  nlp: {
    purpose: "Finds social-engineering cues",
    detail:
      "Readable regular-expression rules check for urgency, fear, authority, credential requests, secrecy, rewards, and financial language.",
  },
  url: {
    purpose: "Inspects links in the body",
    detail:
      "URL heuristics flag signals such as insecure HTTP, raw IP addresses, suspicious words, unusual subdomains, risky top-level domains, and shorteners.",
  },
  metadata: {
    purpose: "Checks sender consistency",
    detail:
      "Sender and Reply-To domains are compared, with extra checks for brand lookalikes, public email services, role-based names, and unusual domain structure.",
  },
};

export default function AboutPage({ isAuthenticated }) {
  return (
    <main className="about-shell">
      <header className="about-header">
        <a className="about-back" href="#console">
          <span aria-hidden="true">←</span>
          {isAuthenticated ? "Back to console" : "Back to sign in"}
        </a>
        <a className="about-brand" href="#console">
          <ShieldIcon />
          <span>THREATLENS</span>
          <b aria-hidden="true">›</b>
          <span>ABOUT</span>
        </a>
      </header>

      <article className="about-content">
        <section className="about-hero">
          <p className="technical-label">FINAL-YEAR PROJECT · METHODOLOGY</p>
          <h1>An explainable, multi-layer approach to email threat detection.</h1>
          <p>
            ThreatLens helps a user inspect a suspicious email without relying on a
            single score alone. It combines a trained content model with three
            readable rule-based layers, then returns both the overall risk and the
            evidence available from each check.
          </p>
        </section>

        <section className="about-section" aria-labelledby="workflow-title">
          <p className="technical-label">HOW IT WORKS</p>
          <h2 id="workflow-title">From email input to an explainable report</h2>
          <ol className="workflow-list">
            <li>
              <span>01</span>
              <div>
                <strong>Submit an email</strong>
                <p>
                  Enter the sender, optional Reply-To, subject, and body, or parse
                  those fields from raw email text or a supported Gmail-style copy.
                </p>
              </div>
            </li>
            <li>
              <span>02</span>
              <div>
                <strong>Run four analysis layers</strong>
                <p>
                  The FastAPI service applies the trained model and the language,
                  URL, and metadata rules to the same message.
                </p>
              </div>
            </li>
            <li>
              <span>03</span>
              <div>
                <strong>Review and retain the result</strong>
                <p>
                  The console shows the component scores and returned reasons, while
                  the authenticated history stores a concise record in SQLite.
                </p>
              </div>
            </li>
          </ol>
        </section>

        <section className="about-section" aria-labelledby="layers-about-title">
          <p className="technical-label">THE FOUR LAYERS</p>
          <h2 id="layers-about-title">Different signals, one report</h2>
          <div className="about-layer-grid">
            {DETECTION_LAYERS.map((layer, index) => (
              <article className="about-layer" key={layer.key}>
                <div className="about-layer-heading">
                  <span>0{index + 1}</span>
                  <div>
                    <small>{LAYER_DETAILS[layer.key].purpose}</small>
                    <h3>{layer.name}</h3>
                  </div>
                </div>
                <p>{LAYER_DETAILS[layer.key].detail}</p>
                <span className="weight-note">{layer.weight}% base weight</span>
              </article>
            ))}
          </div>
        </section>

        <section className="about-section risk-fusion" aria-labelledby="fusion-title">
          <p className="technical-label">RISK FUSION</p>
          <h2 id="fusion-title">How the final score is produced</h2>
          <p>
            Each layer returns a score from 0 to 100. The base score uses the
            project’s current weights. Calibration floors can then raise the result
            when several independent layers trigger, when the ML score is very high,
            or when a business-email-compromise pattern is reinforced by a Reply-To
            mismatch.
          </p>
          <pre>
            <code>{`base score =
  (machine learning × 0.45) +
  (language analysis × 0.20) +
  (URL analysis × 0.25) +
  (metadata analysis × 0.10)

Low Risk:     0–39
Medium Risk: 40–69
High Risk:   70–100`}</code>
          </pre>
        </section>

        <section className="about-split">
          <div className="about-section">
            <p className="technical-label">EXPLAINABILITY</p>
            <h2>What the user can inspect</h2>
            <ul className="about-list">
              <li>All four layer scores and the final risk label.</li>
              <li>Grouped ML, language, URL, and metadata reason strings.</li>
              <li>Influential model terms when the backend returns them.</li>
              <li>Saved numeric results and flat reasons in scan history.</li>
            </ul>
          </div>

          <div className="about-section">
            <p className="technical-label">TECHNOLOGY STACK</p>
            <h2>Current implementation</h2>
            <dl className="stack-list">
              <div>
                <dt>Frontend</dt>
                <dd>React, Vite, Axios, and plain CSS</dd>
              </div>
              <div>
                <dt>Backend</dt>
                <dd>FastAPI, Pydantic, and Python</dd>
              </div>
              <div>
                <dt>Model</dt>
                <dd>scikit-learn TF-IDF and logistic regression</dd>
              </div>
              <div>
                <dt>Storage</dt>
                <dd>SQLite with SQLAlchemy</dd>
              </div>
            </dl>
          </div>
        </section>

        <section className="about-section limitations" aria-labelledby="limits-title">
          <p className="technical-label">IMPORTANT LIMITATIONS</p>
          <h2 id="limits-title">What ThreatLens does not currently do</h2>
          <ul className="about-list">
            <li>
              Results can contain false positives or false negatives and should
              support, not replace, human judgement.
            </li>
            <li>
              The baseline model is trained on the project’s Enron spam dataset and
              may not represent every modern attack style.
            </li>
            <li>
              The current API does not analyse attachments, query threat-intelligence
              services, or validate SPF, DKIM, or DMARC.
            </li>
            <li>
              URL checks examine visible text patterns; they do not safely visit or
              execute links.
            </li>
            <li>
              Saved history retains a body preview and flat findings, not the complete
              grouped explanation from the immediate response.
            </li>
          </ul>
        </section>

        <footer className="about-footer">
          <ConsoleIcon name="info" />
          ThreatLens is an academic prototype for explainable email threat analysis.
        </footer>
      </article>
    </main>
  );
}
