import assert from "node:assert/strict";
import test from "node:test";

import {
  clampScore,
  getExplanationGroups,
  getHistoryCounts,
  getLayerFindingCount,
  getRiskCopy,
  getRiskTone,
} from "./reportUtils.js";

test("clamps report scores to the supported 0 to 100 range", () => {
  assert.equal(clampScore(-12), 0);
  assert.equal(clampScore(44.6), 45);
  assert.equal(clampScore(140), 100);
  assert.equal(clampScore("not a score"), 0);
});

test("uses backend labels and score thresholds for risk tones", () => {
  assert.equal(getRiskTone("High Risk", 12), "high");
  assert.equal(getRiskTone("Medium Risk", 12), "medium");
  assert.equal(getRiskTone("", 39), "low");
  assert.equal(getRiskTone("", 70), "high");
});

test("calculates console counters from real history records", () => {
  assert.deepEqual(
    getHistoryCounts([
      { label: "High Risk", risk_score: 82 },
      { label: "Medium Risk", risk_score: 51 },
      { label: "Low Risk", risk_score: 18 },
      { label: "High Risk", risk_score: 76 },
    ]),
    { total: 4, high: 2, medium: 1, low: 1 },
  );
});

test("keeps grouped API explanations without repeating flat reasons", () => {
  const groups = getExplanationGroups({
    reasons: ["Flat reason"],
    ml_suspicious_words: ["account", "verify"],
    explanation: {
      ml: ["ML reason"],
      nlp: ["NLP reason"],
      url: [],
      metadata: [],
    },
  });

  assert.deepEqual(
    groups.map((group) => group.key),
    ["ml", "nlp"],
  );
  assert.deepEqual(groups[0].terms, ["account", "verify"]);
  assert.deepEqual(groups[0].items, ["ML reason"]);
});

test("falls back to stored flat findings for a history record", () => {
  const groups = getExplanationGroups({
    reasons: ["Stored reason", "Stored reason"],
  });

  assert.equal(groups[0].key, "all");
  assert.deepEqual(groups[0].items, ["Stored reason"]);
});

test("deduplicates layer findings before displaying a count", () => {
  assert.equal(
    getLayerFindingCount(
      { explanation: { url: ["Insecure link", "Insecure link", "Raw IP"] } },
      "url",
    ),
    2,
  );
  assert.equal(getLayerFindingCount({ reasons: ["Flat reason"] }, "url"), null);
});

test("keeps recommended risk wording conservative", () => {
  assert.match(getRiskCopy("Low Risk", 8).message, /cannot guarantee/i);
  assert.match(getRiskCopy("High Risk", 90).verdict, /do not interact/i);
});
