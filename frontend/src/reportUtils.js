export const DETECTION_LAYERS = [
  {
    key: "ml",
    scoreKey: "ml_score",
    name: "Machine Learning",
    shortName: "ML",
    weight: 45,
    summary: "TF-IDF and logistic-regression content model",
  },
  {
    key: "nlp",
    scoreKey: "nlp_score",
    name: "Language Analysis",
    shortName: "NLP",
    weight: 20,
    summary: "Rule checks for social-engineering language",
  },
  {
    key: "url",
    scoreKey: "url_score",
    name: "URL Analysis",
    shortName: "URL",
    weight: 25,
    summary: "Heuristics applied to links in the message body",
  },
  {
    key: "metadata",
    scoreKey: "metadata_score",
    name: "Metadata Analysis",
    shortName: "META",
    weight: 10,
    summary: "Sender and Reply-To consistency checks",
  },
];

export function clampScore(value) {
  const score = Number(value);

  if (!Number.isFinite(score)) {
    return 0;
  }

  return Math.min(100, Math.max(0, Math.round(score)));
}

export function getRiskTone(label, score = 0) {
  const normalizedLabel = String(label ?? "").toLowerCase();

  if (normalizedLabel.includes("high") || clampScore(score) >= 70) {
    return "high";
  }

  if (normalizedLabel.includes("medium") || clampScore(score) >= 40) {
    return "medium";
  }

  return "low";
}

export function getRiskCopy(label, score) {
  const tone = getRiskTone(label, score);

  if (tone === "high") {
    return {
      verdict: "Likely phishing — do not interact",
      message:
        "The combined analysis found strong threat indicators. Treat this message as unsafe until it has been independently verified.",
    };
  }

  if (tone === "medium") {
    return {
      verdict: "Suspicious — verify independently",
      message:
        "Some threat indicators were detected. Check the sender and any requested action using a trusted communication channel.",
    };
  }

  return {
    verdict: "No major threat detected",
    message:
      "The current checks found limited suspicious evidence. This result reduces concern, but it cannot guarantee that an email is safe.",
  };
}

export function getRecommendedActions(label, score) {
  const tone = getRiskTone(label, score);

  if (tone === "high") {
    return [
      "Do not click links, download files, or reply with sensitive information.",
      "Verify the sender through a trusted contact method.",
      "Report the message to the appropriate security or IT team.",
      "Delete or quarantine it if phishing is confirmed.",
    ];
  }

  if (tone === "medium") {
    return [
      "Check the sender address and Reply-To address carefully.",
      "Open the organisation’s official website directly instead of using email links.",
      "Confirm unusual requests through a trusted communication channel.",
    ];
  }

  return [
    "Continue to check unexpected links and requests before acting.",
    "Verify sensitive requests independently, even when the message appears legitimate.",
  ];
}

export function getHistoryCounts(history = []) {
  return history.reduce(
    (counts, item) => {
      const tone = getRiskTone(item.label, item.risk_score);

      counts.total += 1;
      counts[tone] += 1;

      return counts;
    },
    { total: 0, high: 0, medium: 0, low: 0 },
  );
}

export function formatDateTime(value) {
  if (!value) {
    return "";
  }

  const date = new Date(value);

  if (Number.isNaN(date.getTime())) {
    return "";
  }

  return new Intl.DateTimeFormat(undefined, {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(date);
}

function uniqueStrings(items = []) {
  return [...new Set(items.filter((item) => typeof item === "string" && item.trim()))];
}

export function getExplanationGroups(report) {
  const explanation = report?.explanation;

  if (explanation) {
    const groups = DETECTION_LAYERS.map((layer) => ({
      ...layer,
      items: uniqueStrings(explanation[layer.key]),
      terms:
        layer.key === "ml"
          ? uniqueStrings(report.ml_suspicious_words)
          : [],
    })).filter((group) => group.items.length > 0 || group.terms.length > 0);

    if (groups.length > 0) {
      return groups;
    }
  }

  return [
    {
      key: "all",
      name: "All Findings",
      items: uniqueStrings(report?.reasons),
      terms: [],
    },
  ];
}

export function getLayerFindingCount(report, layerKey) {
  const items = report?.explanation?.[layerKey];

  return Array.isArray(items) ? uniqueStrings(items).length : null;
}
