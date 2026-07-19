const EMPTY_EMAIL = {
  sender: "",
  reply_to: "",
  subject: "",
  body: "",
};

const HEADER_FIELD_MAP = {
  from: "sender",
  "reply-to": "reply_to",
  "reply to": "reply_to",
  subject: "subject",
};

const EMAIL_ADDRESS_PATTERN =
  /[A-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?(?:\.[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?)+/i;

function stripMarkdownMarkers(value) {
  return value
    .replace(/\*\*([^*\n]+)\*\*/g, "$1")
    .replace(/__([^_\n]+)__/g, "$1")
    .trim();
}

function findEmailAddress(value) {
  const markdownMailtoMatch = value.match(/\]\(\s*mailto:([^)]+)\)/i);
  const markdownMailtoAddress = markdownMailtoMatch?.[1].match(EMAIL_ADDRESS_PATTERN)?.[0];

  if (markdownMailtoAddress) {
    return markdownMailtoAddress;
  }

  const angleBracketMatch = value.match(/<\s*([^<>]+?)\s*>/);
  const angleBracketAddress = angleBracketMatch?.[1].match(EMAIL_ADDRESS_PATTERN)?.[0];

  if (angleBracketAddress) {
    return angleBracketAddress;
  }

  return value.match(EMAIL_ADDRESS_PATTERN)?.[0] ?? "";
}

function extractEmailAddress(value) {
  return findEmailAddress(value) || stripMarkdownMarkers(value);
}

function findGmailSenderAddress(value) {
  const hasMarkdownMailto = /\]\(\s*mailto:[^)]+\)/i.test(value);
  const hasAngleBracketAddress = /<\s*[^<>]+@[^<>]+\s*>/.test(value);

  return hasMarkdownMailto || hasAngleBracketAddress ? findEmailAddress(value) : "";
}

function cleanMetadataLine(line) {
  return stripMarkdownMarkers(line).trim();
}

function isGmailChromeLine(value) {
  const normalizedValue = value.toLowerCase();

  return (
    normalizedValue === "none selected" ||
    normalizedValue === "skip to content" ||
    normalizedValue === "using gmail with screen readers" ||
    /^\[(?:skip to content|using gmail with screen readers)\]\(/i.test(value) ||
    /^\d[\d,]*\s+of\s+\d[\d,]*$/i.test(value)
  );
}

function isGmailDateLine(value) {
  const cleanedValue = cleanMetadataLine(value);

  return (
    /\b(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun)(?:day)?\b/i.test(cleanedValue) ||
    /\b(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)(?:uary|ruary|ch|il|e|y|ust|tember|ober|ember)?\b/i.test(
      cleanedValue,
    ) ||
    /\b(?:today|yesterday)\b/i.test(cleanedValue) ||
    /\b\d{1,2}:\d{2}\s*(?:am|pm)\b/i.test(cleanedValue)
  );
}

function parseGmailVisibleCopy(lines) {
  const inboxIndex = lines.findIndex(
    (line) => cleanMetadataLine(line).toLowerCase() === "inbox",
  );

  if (inboxIndex === -1) {
    return null;
  }

  let subject = "";

  for (let index = inboxIndex - 1; index >= Math.max(0, inboxIndex - 8); index -= 1) {
    const candidate = cleanMetadataLine(lines[index]);

    if (candidate && !isGmailChromeLine(candidate)) {
      subject = candidate;
      break;
    }
  }

  if (!subject) {
    return null;
  }

  const senderSearchEnd = Math.min(lines.length, inboxIndex + 10);
  let sender = "";
  let senderIndex = -1;

  for (let index = inboxIndex + 1; index < senderSearchEnd; index += 1) {
    const candidate = findGmailSenderAddress(lines[index]);

    if (candidate) {
      sender = candidate;
      senderIndex = index;
      break;
    }
  }

  if (senderIndex === -1) {
    return null;
  }

  const recipientSearchEnd = Math.min(lines.length, senderIndex + 10);
  let recipientIndex = -1;

  for (let index = senderIndex + 1; index < recipientSearchEnd; index += 1) {
    if (/^to\s+me$/i.test(cleanMetadataLine(lines[index]))) {
      recipientIndex = index;
      break;
    }
  }

  const hasDateMetadata = lines
    .slice(senderIndex + 1, recipientIndex === -1 ? senderIndex + 1 : recipientIndex)
    .some(isGmailDateLine);

  if (recipientIndex === -1 || !hasDateMetadata) {
    return null;
  }

  let replyTo = "";

  for (let index = senderIndex + 1; index <= recipientIndex; index += 1) {
    const replyToMatch = lines[index].match(/^\s*reply(?:-|\s)to\s*:\s*(.*)$/i);

    if (replyToMatch) {
      replyTo = extractEmailAddress(replyToMatch[1]);
      break;
    }
  }

  let bodyStart = recipientIndex + 1;

  while (bodyStart < lines.length && lines[bodyStart].trim() === "") {
    bodyStart += 1;
  }

  return {
    sender,
    reply_to: replyTo,
    subject: stripMarkdownMarkers(subject),
    body: lines.slice(bodyStart).join("\n").trim(),
  };
}

export function parseEmailText(rawEmail) {
  const normalizedEmail = rawEmail.replace(/\r\n?/g, "\n").trimStart();
  const lines = normalizedEmail.split("\n");
  const parsedEmail = { ...EMPTY_EMAIL };
  const separatorIndex = lines.findIndex((line) => line.trim() === "");
  const headerLimit = separatorIndex === -1 ? lines.length : separatorIndex;
  let currentField = null;
  let foundHeader = false;
  let bodyStart = separatorIndex === -1 ? lines.length : separatorIndex + 1;

  for (let index = 0; index < headerLimit; index += 1) {
    const line = lines[index];

    if (/^[ \t]/.test(line) && currentField) {
      parsedEmail[currentField] = `${parsedEmail[currentField]} ${line.trim()}`.trim();

      if (separatorIndex === -1) {
        bodyStart = index + 1;
      }

      continue;
    }

    const headerMatch = line.match(
      /^([A-Za-z][A-Za-z0-9-]*(?:[ \t]+[A-Za-z][A-Za-z0-9-]*)?)[ \t]*:[ \t]*(.*)$/,
    );

    if (headerMatch) {
      const headerName = headerMatch[1].toLowerCase().replace(/[ \t]+/g, " ");
      currentField = HEADER_FIELD_MAP[headerName] ?? null;

      if (currentField) {
        parsedEmail[currentField] = headerMatch[2].trim();
        foundHeader = true;

        if (separatorIndex === -1) {
          bodyStart = index + 1;
        }
      }

      continue;
    }

    currentField = null;

    if (separatorIndex === -1 && foundHeader) {
      bodyStart = index;
      break;
    }
  }

  if (!foundHeader) {
    const gmailEmail = parseGmailVisibleCopy(lines);

    if (gmailEmail) {
      return gmailEmail;
    }

    bodyStart = 0;
  }

  parsedEmail.sender = extractEmailAddress(parsedEmail.sender);
  parsedEmail.reply_to = extractEmailAddress(parsedEmail.reply_to);
  parsedEmail.subject = stripMarkdownMarkers(parsedEmail.subject);
  parsedEmail.body = lines.slice(bodyStart).join("\n").trim();

  return parsedEmail;
}

function formatFieldList(fields) {
  if (fields.length < 2) {
    return fields[0] ?? "";
  }

  return `${fields.slice(0, -1).join(", ")} and ${fields.at(-1)}`;
}

export function getParserStatus(parsedEmail, currentEmail = parsedEmail) {
  const parsedFields = [
    ["sender", "sender"],
    ["reply_to", "Reply-To"],
    ["subject", "subject"],
    ["body", "body"],
  ]
    .filter(([field]) => parsedEmail[field].trim())
    .map(([, label]) => label);
  const missingFields = [
    ["sender", "sender"],
    ["subject", "subject"],
    ["body", "body"],
  ]
    .filter(([field]) => !currentEmail[field].trim())
    .map(([, label]) => label);
  const statusParts = [
    parsedFields.length
      ? `Parsed ${formatFieldList(parsedFields)}.`
      : "No email fields were parsed.",
  ];

  if (!parsedEmail.reply_to.trim()) {
    statusParts.push("Reply-To was not found.");
  }

  statusParts.push(
    `Missing required fields: ${missingFields.length ? formatFieldList(missingFields) : "none"}.`,
  );

  return statusParts.join(" ");
}
