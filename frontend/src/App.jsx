import { useState } from "react";
import { scanEmail } from "./api";
import "./App.css";

const SAMPLES = {
  clean: {sender: "updates@stripe.com", subject: "Monthly report", 
            body: "Your monthly report is ready. View it here: https://dashboard.stripe.com/reports/monthly"},
  malicious: {sender: "support@paypa1-secure.com", subject: "URGENT verify",
                body: "Your account has been compromised. Verify your information here: http://192.168.4.21/login"},
};

export default function App() {
  const [form, setForm] = useState({sender: "", subject: "", body: ""});
  const [report, setReport] = useState(null);
  const [busy, setBusy] = useState(false);

  const submit = async (e) => {
    e.preventDefault();
    setBusy(true);
    try {setReport(await scanEmail(form));}
    finally {setBusy(false);}
}

  return (
    <div className = "container">
      <h1>Threatlens</h1>

      <div className="samples">
        <h2>Sample Emails</h2>
        <button onClick={() => setForm(SAMPLES.clean)}>Load Clean Sample</button>
        <button onClick={() => setForm(SAMPLES.malicious)}>Load Malicious Sample</button>
      </div>

      <form onSubmit={submit}>
        <input placeholder = "From"
          value={form.sender}
          onChange={(e) => setForm({...form, sender: e.target.value})} />
        <input placeholder = "Subject"
          value={form.subject}
          onChange={(e) => setForm({...form, subject: e.target.value})} />
        <textarea placeholder = "Email Body" rows = {8} required
          value={form.body}
          onChange={(e) => setForm({...form, body: e.target.value})} /> 
        <button type="submit" disabled={busy}>{busy ? "Scanning..." : "Scan Email"}</button>
      </form>

      {report && (
        <div className="report">
          <h2>Risk: {report.final_score}/100 - {report.risk_level}</h2>
          <h3>NLP Findings: ({report.nlp.score})</h3>
          <ul>
            {report.nlp.findings.map((f) => <li key = {f.id}>{f.title} - {f.detail}</li>)}
          </ul>
          <h3>URL Findings: ({report.url.score})</h3>
          <ul>
            {report.url.findings.map((f) => <li key = {f.id}>{f.title} - {f.detail}</li>)}
          </ul> 
        </div>
      )}
    </div>
  );
}











































/*import reactLogo from './assets/react.svg'
import viteLogo from './assets/vite.svg'
import heroImg from './assets/hero.png'
import './App.css'

function App() {
  const [count, setCount] = useState(0)

  return (
    <>
      <section id="center">
        <div className="hero">
          <img src={heroImg} className="base" width="170" height="179" alt="" />
          <img src={reactLogo} className="framework" alt="React logo" />
          <img src={viteLogo} className="vite" alt="Vite logo" />
        </div>
        <div>
          <h1>Get started</h1>
          <p>
            Edit <code>src/App.jsx</code> and save to test <code>HMR</code>
          </p>
        </div>
        <button
          type="button"
          className="counter"
          onClick={() => setCount((count) => count + 1)}
        >
          Count is {count}
        </button>
      </section>

      <div className="ticks"></div>

      <section id="next-steps">
        <div id="docs">
          <svg className="icon" role="presentation" aria-hidden="true">
            <use href="/icons.svg#documentation-icon"></use>
          </svg>
          <h2>Documentation</h2>
          <p>Your questions, answered</p>
          <ul>
            <li>
              <a href="https://vite.dev/" target="_blank">
                <img className="logo" src={viteLogo} alt="" />
                Explore Vite
              </a>
            </li>
            <li>
              <a href="https://react.dev/" target="_blank">
                <img className="button-icon" src={reactLogo} alt="" />
                Learn more
              </a>
            </li>
          </ul>
        </div>
        <div id="social">
          <svg className="icon" role="presentation" aria-hidden="true">
            <use href="/icons.svg#social-icon"></use>
          </svg>
          <h2>Connect with us</h2>
          <p>Join the Vite community</p>
          <ul>
            <li>
              <a href="https://github.com/vitejs/vite" target="_blank">
                <svg
                  className="button-icon"
                  role="presentation"
                  aria-hidden="true"
                >
                  <use href="/icons.svg#github-icon"></use>
                </svg>
                GitHub
              </a>
            </li>
            <li>
              <a href="https://chat.vite.dev/" target="_blank">
                <svg
                  className="button-icon"
                  role="presentation"
                  aria-hidden="true"
                >
                  <use href="/icons.svg#discord-icon"></use>
                </svg>
                Discord
              </a>
            </li>
            <li>
              <a href="https://x.com/vite_js" target="_blank">
                <svg
                  className="button-icon"
                  role="presentation"
                  aria-hidden="true"
                >
                  <use href="/icons.svg#x-icon"></use>
                </svg>
                X.com
              </a>
            </li>
            <li>
              <a href="https://bsky.app/profile/vite.dev" target="_blank">
                <svg
                  className="button-icon"
                  role="presentation"
                  aria-hidden="true"
                >
                  <use href="/icons.svg#bluesky-icon"></use>
                </svg>
                Bluesky
              </a>
            </li>
          </ul>
        </div>
      </section>

      <div className="ticks"></div>
      <section id="spacer"></section>
    </>
  )
}

export default App
*/