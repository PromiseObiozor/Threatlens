import assert from "node:assert/strict";
import test from "node:test";

import { getParserStatus, parseEmailText } from "./emailParser.js";

test("parses standard raw headers and body", () => {
  const parsed = parseEmailText(`From: Example Sender <sender@example.com>
Reply-To: replies@example.com
Subject: Example subject

Hello from the body.`);

  assert.deepEqual(parsed, {
    sender: "sender@example.com",
    reply_to: "replies@example.com",
    subject: "Example subject",
    body: "Hello from the body.",
  });
});

test("parses Gmail visible-copy text without including Gmail interface metadata", () => {
  const parsed = parseEmailText(`None selected

[Skip to content](https://mail.google.com/mail/u/0/)
[Using Gmail with screen readers](https://mail.google.com/mail/u/0/)
17 of 17,298
**Remote Job Alert: Administrative Clerk - Full Time - Work From Home at TMF Health Quality Institute**
**Inbox**

**remot** [alerts@workremot.com](mailto:alerts@workremot.com) **Unsubscribe**
Mon, Jul 13, 6:43 PM (2 days ago)
to me

===============================
REMOTE JOB ALERT
================

July 13, 2026

**Administrative Clerk - Full Time - Work From Home**
Remote

Remot • Wyoming, USA

You are receiving this email because you subscribed to remote job alerts.`);

  assert.equal(parsed.sender, "alerts@workremot.com");
  assert.equal(parsed.reply_to, "");
  assert.equal(
    parsed.subject,
    "Remote Job Alert: Administrative Clerk - Full Time - Work From Home at TMF Health Quality Institute",
  );
  assert.match(parsed.body, /^={10,}\nREMOTE JOB ALERT/);
  assert.match(parsed.body, /Remot • Wyoming, USA/);
  assert.doesNotMatch(parsed.body, /None selected|Skip to content|\bInbox\b|Mon, Jul 13|to me/);
});

test("leaves Reply-To blank when the header is absent", () => {
  const parsed = parseEmailText(`From: sender@example.com
Subject: No reply address

Body text.`);

  assert.equal(parsed.reply_to, "");
  assert.equal(
    getParserStatus(parsed),
    "Parsed sender, subject and body. Reply-To was not found. Missing required fields: none.",
  );
});

test("reports a malformed structured email with no sender", () => {
  const parsed = parseEmailText(`Subject: Missing sender

Body text.`);

  assert.equal(parsed.sender, "");
  assert.equal(
    getParserStatus(parsed),
    "Parsed subject and body. Reply-To was not found. Missing required fields: sender.",
  );
});

test("removes Markdown markers and extracts a literal angle-bracket sender", () => {
  const parsed = parseEmailText(`**Markdown subject**
**Inbox**

**Sender Name** <marked@example.com> **Unsubscribe**
Tue, Jul 14, 9:15 AM (1 day ago)
to me

Actual message body.`);

  assert.equal(parsed.sender, "marked@example.com");
  assert.equal(parsed.subject, "Markdown subject");
  assert.equal(parsed.body, "Actual message body.");
});

test("extracts Markdown mailto links from structured From headers", () => {
  const parsed = parseEmailText(`From: [sender@example.com](mailto:sender@example.com)
Subject: **Marked subject**

Body text.`);

  assert.equal(parsed.sender, "sender@example.com");
  assert.equal(parsed.subject, "Marked subject");
});

test("does not invent a Gmail sender from an email address in the body", () => {
  const parsed = parseEmailText(`Missing sender
Inbox

Mon, Jul 13, 6:43 PM (2 days ago)
to me

Contact jobs@example.com for details.
To apply, click below.
Keep this body line.`);

  assert.equal(parsed.sender, "");
  assert.match(parsed.body, /Contact jobs@example.com for details\./);
  assert.match(parsed.body, /To apply, click below\./);
});

test("does not treat a body line beginning with To as Gmail recipient metadata", () => {
  const parsed = parseEmailText(`Example subject
Inbox

Sender <sender@example.com>
Mon, Jul 13, 6:43 PM (2 days ago)

To apply, click below.
Keep this body line.`);

  assert.equal(parsed.sender, "");
  assert.match(parsed.body, /To apply, click below\./);
  assert.match(parsed.body, /Keep this body line\./);
});

test("preserves double underscores that are not paired Markdown markers", () => {
  const parsed = parseEmailText(`From: sender@example.com
Subject: Build test__name failed

Body text.`);

  assert.equal(parsed.subject, "Build test__name failed");
});

test("updates currently missing fields without changing the parser result summary", () => {
  const parsed = parseEmailText(`Subject: Missing sender

Body text.`);
  const edited = { ...parsed, sender: "manual@example.com" };

  assert.equal(
    getParserStatus(parsed, edited),
    "Parsed subject and body. Reply-To was not found. Missing required fields: none.",
  );
});
