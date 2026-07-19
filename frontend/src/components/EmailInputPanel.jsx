import {
  ConsoleIcon,
  LoadingSpinner,
  SectionHeading,
} from "./ConsolePrimitives";

export default function EmailInputPanel({
  mode,
  form,
  rawEmail,
  parserStatus,
  parserWarning,
  busy,
  message,
  onModeChange,
  onFieldChange,
  onRawEmailChange,
  onParse,
  onLoadSample,
  onClear,
  onSubmit,
}) {
  const isFieldsMode = mode === "fields";

  return (
    <section className="workspace-section input-section" aria-labelledby="input-heading">
      <SectionHeading
        id="input-heading"
        note={isFieldsMode ? "Enter supported email fields" : "Parse headers and message content"}
        number="01"
        title="INPUT"
      />

      <div className="console-panel input-panel">
        <div className="input-tabs" aria-label="Email input method">
          <button
            aria-pressed={isFieldsMode}
            className={isFieldsMode ? "active" : ""}
            disabled={busy}
            onClick={() => onModeChange("fields")}
            type="button"
          >
            Fields
          </button>
          <button
            aria-pressed={!isFieldsMode}
            className={!isFieldsMode ? "active" : ""}
            disabled={busy}
            onClick={() => onModeChange("raw")}
            type="button"
          >
            <ConsoleIcon name="paste" />
            Paste Raw Email
          </button>
        </div>

        <div className="sample-toolbar">
          <span className="technical-label">SAMPLES</span>
          <div className="sample-actions">
            <button
              className="sample-chip sample-clean"
              disabled={busy}
              onClick={() => onLoadSample("clean")}
              type="button"
            >
              Clean
            </button>
            <button
              className="sample-chip sample-suspicious"
              disabled={busy}
              onClick={() => onLoadSample("suspicious")}
              type="button"
            >
              Suspicious
            </button>
            <button
              className="sample-chip sample-malicious"
              disabled={busy}
              onClick={() => onLoadSample("malicious")}
              type="button"
            >
              Malicious
            </button>
          </div>
          <button className="clear-button" disabled={busy} onClick={onClear} type="button">
            Clear
          </button>
        </div>

        <form className="scan-form" onSubmit={onSubmit}>
          {isFieldsMode ? (
            <div className="fields-email-panel">
              {parserStatus && (
                <p
                  className={`parser-status${parserWarning ? " warning" : ""}`}
                  role="status"
                >
                  <ConsoleIcon name={parserWarning ? "info" : "check"} />
                  {parserStatus}
                </p>
              )}

              <div className="field-pair">
                <div className="form-field">
                  <label htmlFor="email-sender">
                    Sender / From <span className="required-mark">*</span>
                  </label>
                  <input
                    autoComplete="off"
                    disabled={busy}
                    id="email-sender"
                    onChange={(event) => onFieldChange("sender", event.target.value)}
                    placeholder="sender@example.com"
                    required
                    spellCheck="false"
                    type="email"
                    value={form.sender}
                  />
                </div>

                <div className="form-field">
                  <label htmlFor="email-reply-to">Reply-To</label>
                  <input
                    autoComplete="off"
                    disabled={busy}
                    id="email-reply-to"
                    onChange={(event) => onFieldChange("reply_to", event.target.value)}
                    placeholder="Optional reply address"
                    spellCheck="false"
                    type="email"
                    value={form.reply_to}
                  />
                </div>
              </div>

              <div className="form-field">
                <label htmlFor="email-subject">
                  Subject <span className="required-mark">*</span>
                </label>
                <input
                  disabled={busy}
                  id="email-subject"
                  onChange={(event) => onFieldChange("subject", event.target.value)}
                  placeholder="Email subject line"
                  required
                  type="text"
                  value={form.subject}
                />
              </div>

              <div className="form-field">
                <label htmlFor="email-body">
                  Email body <span className="required-mark">*</span>
                </label>
                <textarea
                  disabled={busy}
                  id="email-body"
                  onChange={(event) => onFieldChange("body", event.target.value)}
                  placeholder="Paste the message body here…"
                  required
                  rows={12}
                  value={form.body}
                />
              </div>
            </div>
          ) : (
            <div className="raw-email-panel">
              <div className="raw-email-instructions">
                <p className="technical-label">FULL EMAIL SOURCE OR GMAIL COPY</p>
                <p>
                  Paste the email headers and body. Parsed values remain editable before a scan.
                </p>
              </div>

              <label className="sr-only" htmlFor="raw-email">
                Raw email content
              </label>
              <textarea
                className="raw-email-input"
                disabled={busy}
                id="raw-email"
                onChange={(event) => onRawEmailChange(event.target.value)}
                placeholder={
                  "From: Example Sender <sender@example.com>\nReply-To: replies@example.com\nSubject: Example subject\n\nEmail body…"
                }
                rows={16}
                value={rawEmail}
              />

              <button
                className="secondary-button parse-button"
                disabled={busy}
                onClick={onParse}
                type="button"
              >
                <ConsoleIcon name="paste" />
                Parse &amp; Fill Fields
              </button>
            </div>
          )}

          {message && (
            <p className="form-message" role="alert">
              {message}
            </p>
          )}

          {isFieldsMode && (
            <button className="primary-button scan-button" disabled={busy} type="submit">
              {busy ? (
                <>
                  <LoadingSpinner />
                  Analysing email…
                </>
              ) : (
                <>
                  <ConsoleIcon name="scan" />
                  Run Threat Analysis
                </>
              )}
            </button>
          )}
        </form>
      </div>
    </section>
  );
}
