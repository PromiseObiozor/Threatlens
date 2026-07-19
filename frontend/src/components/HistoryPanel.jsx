import { formatDateTime, getRiskTone } from "../reportUtils";
import {
  ConsoleIcon,
  LoadingSpinner,
  SectionHeading,
} from "./ConsolePrimitives";

export default function HistoryPanel({
  history,
  loading,
  deletingId,
  selectedId,
  message,
  interactionDisabled,
  onSelect,
  onDelete,
  onRefresh,
}) {
  return (
    <section className="workspace-section history-section" aria-labelledby="history-heading">
      <SectionHeading
        id="history-heading"
        note={`${history.length} ${history.length === 1 ? "scan" : "scans"}`}
        number="03"
        title="HISTORY"
      />

      <div className="console-panel history-panel" aria-busy={loading || Boolean(deletingId)}>
        <div className="history-toolbar">
          <p>Saved to the authenticated user’s local database.</p>
          <button
            aria-label="Refresh scan history"
            className="icon-button"
            disabled={loading || interactionDisabled}
            onClick={onRefresh}
            title="Refresh history"
            type="button"
          >
            {loading ? <LoadingSpinner /> : <ConsoleIcon name="refresh" />}
          </button>
        </div>

        {message && (
          <p className="history-message" role="alert">
            {message}
          </p>
        )}

        {loading && history.length === 0 ? (
          <div className="history-empty">
            <LoadingSpinner />
            <p>Loading saved scans…</p>
          </div>
        ) : history.length > 0 ? (
          <ul className="history-list">
            {history.map((item) => {
              const tone = getRiskTone(item.label, item.risk_score);
              const isSelected = selectedId === item.id;
              const isDeleting = deletingId === item.id;

              return (
                <li
                  className={`${isSelected ? "selected" : ""} history-${tone}`}
                  key={item.id}
                >
                  <button
                    aria-pressed={isSelected}
                    className="history-select"
                    disabled={interactionDisabled}
                    onClick={() => onSelect(item)}
                    type="button"
                  >
                    <span className={`history-score score-box-${tone}`}>
                      {item.risk_score}
                    </span>
                    <span className="history-copy">
                      <strong>{item.subject || "No subject"}</strong>
                      <span>{item.sender}</span>
                      <small>
                        <ConsoleIcon name="clock" />
                        {formatDateTime(item.created_at) || "Date unavailable"}
                      </small>
                    </span>
                    <span className={`history-label label-${tone}`}>{item.label}</span>
                  </button>

                  <button
                    aria-label={`Delete scan ${item.subject || item.id}`}
                    className="history-delete"
                    disabled={interactionDisabled}
                    onClick={() => onDelete(item)}
                    title="Delete scan"
                    type="button"
                  >
                    {isDeleting ? <LoadingSpinner /> : <ConsoleIcon name="trash" />}
                  </button>
                </li>
              );
            })}
          </ul>
        ) : (
          <div className="history-empty">
            <ConsoleIcon name="clock" />
            <h3>No saved scans</h3>
            <p>Run your first analysis to populate this history.</p>
          </div>
        )}
      </div>
    </section>
  );
}
