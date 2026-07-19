export function ShieldIcon({ className = "" }) {
  return (
    <svg
      aria-hidden="true"
      className={className}
      fill="none"
      viewBox="0 0 24 24"
    >
      <path
        d="M12 3 19 6v5.2c0 4.4-2.7 7.7-7 9.8-4.3-2.1-7-5.4-7-9.8V6l7-3Z"
        stroke="currentColor"
        strokeLinejoin="round"
        strokeWidth="1.8"
      />
      <path
        d="m9.2 12 1.7 1.7 3.9-4"
        stroke="currentColor"
        strokeLinecap="round"
        strokeLinejoin="round"
        strokeWidth="1.8"
      />
    </svg>
  );
}

export function ConsoleIcon({ name, className = "" }) {
  let content;

  if (name === "database") {
    content = (
      <>
        <ellipse cx="12" cy="5" rx="7" ry="3" />
        <path d="M5 5v6c0 1.7 3.1 3 7 3s7-1.3 7-3V5" />
        <path d="M5 11v6c0 1.7 3.1 3 7 3s7-1.3 7-3v-6" />
      </>
    );
  } else if (name === "pulse") {
    content = <path d="M3 12h4l2.2-5 4.1 10 2.2-5H21" />;
  } else if (name === "info") {
    content = (
      <>
        <circle cx="12" cy="12" r="9" />
        <path d="M12 11v5" />
        <path d="M12 8h.01" />
      </>
    );
  } else if (name === "logout") {
    content = (
      <>
        <path d="M10 5H5v14h5" />
        <path d="m14 8 4 4-4 4" />
        <path d="M9 12h9" />
      </>
    );
  } else if (name === "trash") {
    content = (
      <>
        <path d="M5 7h14" />
        <path d="M9 7V4h6v3" />
        <path d="m7 7 1 13h8l1-13" />
        <path d="M10 11v5M14 11v5" />
      </>
    );
  } else if (name === "refresh") {
    content = (
      <>
        <path d="M20 7v5h-5" />
        <path d="M4 17v-5h5" />
        <path d="M18.2 9A7 7 0 0 0 6.4 6.4L4 9" />
        <path d="M5.8 15A7 7 0 0 0 17.6 17.6L20 15" />
      </>
    );
  } else if (name === "scan") {
    content = (
      <>
        <path d="M4 8V4h4M16 4h4v4M20 16v4h-4M8 20H4v-4" />
        <path d="M7 12h10" />
        <path d="m13 8 4 4-4 4" />
      </>
    );
  } else if (name === "clock") {
    content = (
      <>
        <circle cx="12" cy="12" r="9" />
        <path d="M12 7v5l3 2" />
      </>
    );
  } else if (name === "paste") {
    content = (
      <>
        <path d="M9 5h6v3H9z" />
        <path d="M8 6H6v14h12V6h-2" />
        <path d="M9 12h6M9 16h4" />
      </>
    );
  } else if (name === "check") {
    content = (
      <>
        <circle cx="12" cy="12" r="9" />
        <path d="m8 12 2.5 2.5L16 9" />
      </>
    );
  } else {
    content = <path d="M5 12h14" />;
  }

  return (
    <svg
      aria-hidden="true"
      className={className}
      fill="none"
      stroke="currentColor"
      strokeLinecap="round"
      strokeLinejoin="round"
      strokeWidth="1.7"
      viewBox="0 0 24 24"
    >
      {content}
    </svg>
  );
}

export function SectionHeading({ id, number, title, note }) {
  return (
    <div className="section-heading">
      <h2 id={id}>
        <span>{number}</span>
        <span aria-hidden="true">·</span>
        {title}
      </h2>
      {note && <p>{note}</p>}
    </div>
  );
}

export function LoadingSpinner() {
  return <span aria-hidden="true" className="loading-spinner" />;
}
