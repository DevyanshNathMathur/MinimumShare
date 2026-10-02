// MinimumShare — rules.js
// Detection patterns, context policy, scoring, redaction, and demo scenarios.

(function () {

  // ─── Placeholders ──────────────────────────────────────────────────────────

  const PLACEHOLDERS = {
    email:      '[EMAIL]',
    phone:      '[PHONE]',
    otp:        '[OTP REMOVED]',
    upi:        '[UPI ID]',
    card:       '[PAYMENT DETAILS REMOVED]',
    password:   '[PASSWORD REMOVED]',
    apiKey:     '[API KEY REMOVED]',
    ipv4:       '[IP ADDRESS]',
    url:        '[URL]',
    longId:     '[ID NUMBER]',
    customTerm: '[PROTECTED TERM]',
  };

  // ─── Category map ───────────────────────────────────────────────────────────

  const CATEGORY_MAP = {
    email:      'Contact',
    phone:      'Contact',
    otp:        'Authentication',
    upi:        'Financial',
    card:       'Financial',
    password:   'Authentication',
    apiKey:     'Technical',
    ipv4:       'Technical',
    url:        'Technical',
    longId:     'Identifiers',
    customTerm: 'Other',
  };

  // ─── Context recommendation labels ─────────────────────────────────────────

  const CONTEXT_LABELS = {
    publicPost:      'Public Post',
    aiChatbot:       'AI / Chatbot',
    unknownPerson:   'Unknown Person',
    customerSupport: 'Customer Support',
    jobApplication:  'Job Application',
  };

  // ─── Policy matrix ──────────────────────────────────────────────────────────
  // [publicPost, aiChatbot, unknownPerson, customerSupport, jobApplication]

  const POLICY = {
    email:      ['avoidSharing', 'avoidSharing', 'avoidSharing', 'reviewFirst',  'likelyNeeded'],
    phone:      ['avoidSharing', 'avoidSharing', 'avoidSharing', 'reviewFirst',  'likelyNeeded'],
    otp:        ['neverShare',   'neverShare',   'neverShare',   'neverShare',   'neverShare'],
    upi:        ['avoidSharing', 'avoidSharing', 'avoidSharing', 'reviewFirst',  'avoidSharing'],
    card:       ['neverShare',   'neverShare',   'neverShare',   'neverShare',   'neverShare'],
    password:   ['neverShare',   'neverShare',   'neverShare',   'neverShare',   'neverShare'],
    apiKey:     ['neverShare',   'neverShare',   'neverShare',   'neverShare',   'neverShare'],
    ipv4:       ['avoidSharing', 'reviewFirst',  'avoidSharing', 'reviewFirst',  'reviewFirst'],
    url:        ['reviewFirst',  'reviewFirst',  'reviewFirst',  'reviewFirst',  'reviewFirst'],
    longId:     ['avoidSharing', 'avoidSharing', 'avoidSharing', 'reviewFirst',  'reviewFirst'],
    customTerm: ['neverShare',   'neverShare',   'neverShare',   'neverShare',   'neverShare'],
  };

  const CONTEXT_ORDER = ['publicPost', 'aiChatbot', 'unknownPerson', 'customerSupport', 'jobApplication'];

  function getLabel(type, context) {
    const idx = CONTEXT_ORDER.indexOf(context);
    return POLICY[type][idx < 0 ? 0 : idx];
  }

  // ─── Score weights ──────────────────────────────────────────────────────────

  const LABEL_WEIGHT = { neverShare: 40, avoidSharing: 20, reviewFirst: 8, likelyNeeded: 2 };

  const CONTEXT_MULTIPLIER = {
    publicPost:      1.2,
    unknownPerson:   1.2,
    aiChatbot:       1.0,
    customerSupport: 0.9,
    jobApplication:  0.9,
  };

  // ─── Overlap priority ───────────────────────────────────────────────────────
  // Lower index = higher priority (wins when ranges overlap)

  const OVERLAP_PRIORITY = ['card', 'otp', 'password', 'apiKey', 'email', 'upi',
                             'phone', 'ipv4', 'url', 'longId', 'customTerm'];

  // ─── Detection patterns ─────────────────────────────────────────────────────

  const RE_EMAIL = /[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/g;

  // UPI must end with a known VPA suffix, preventing ordinary email overlap
  const RE_UPI = /[a-zA-Z0-9.\-_]+@(?:upi|oksbi|okaxis|okhdfcbank|okicici|paytm|ybl|ibl|axl|apl|waicici|wahdfc|waaxis|ikwallet|aubank|freecharge|indus|kotak|sbi|rbl|hsbc|citi|federal|airtel|jio)/g;

  const RE_PHONE = /(?:\+?\d{1,3}[\s\-.])?(?:\(?\d{3,5}\)?[\s\-.]?)?\d{3,5}[\s\-.]?\d{4,5}(?!\d)/g;
  const PHONE_MIN_DIGITS = 10;

  const RE_IPV4 = /\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b/g;

  const RE_URL = /https?:\/\/[^\s"'<>]+/g;

  // Card: 13–19 digits, optional space/hyphen separators
  const RE_CARD = /\b(?:\d{4}[\s\-]?){3,4}\d{1,4}\b/g;

  // Password: preceded by a label keyword
  const RE_PASSWORD = /(?:password|passwd|pwd|pass|secret|credentials?)[\s:=]+([^\s\n]{6,})/gi;

  // API key: preceded by a label keyword, followed by a token value.
  // Separator accepts colon/equals/whitespace or natural-language "is".
  const RE_API_KEY = /(?:api[\s_\-]?key|apikey|access[\s_\-]?token|secret[\s_\-]?key|auth[\s_\-]?token|bearer[\s_\-]?token|token)(?:\s+is\s+|[\s:=]+)([^\s\n]{8,})/gi;

  // OTP: 4–8 digit code with relevant surrounding wording
  const RE_OTP_CODE = /\b(\d{4,8})\b/g;
  const OTP_KEYWORDS = /\b(?:otp|one[\s\-]time[\s\-](?:password|code|pin)?|verification[\s\-]code|verify[\s\-]code|security[\s\-]code|login[\s\-]code|authentication[\s\-]code|passcode|auth[\s\-]code)\b/i;
  const OTP_WINDOW = 120;

  // Long ID: 9–20 digit standalone sequence (not already captured as card)
  const RE_LONG_ID = /\b\d{9,20}\b/g;

  // ─── Luhn check ─────────────────────────────────────────────────────────────

  function luhnCheck(str) {
    const digits = str.replace(/\D/g, '');
    if (digits.length < 13 || digits.length > 19) return false;
    let sum = 0;
    let alt = false;
    for (let i = digits.length - 1; i >= 0; i--) {
      let n = parseInt(digits[i], 10);
      if (alt) { n *= 2; if (n > 9) n -= 9; }
      sum += n;
      alt = !alt;
    }
    return sum % 10 === 0;
  }

  // ─── Phone digit count ──────────────────────────────────────────────────────

  function countDigits(str) {
    return (str.match(/\d/g) || []).length;
  }

  // ─── Escape string for use in RegExp ────────────────────────────────────────

  function escapeRegex(str) {
    return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  }

  // ─── Raw detection ──────────────────────────────────────────────────────────
  // Returns array of { type, value, index, length } — unresolved, unannotated.

  function detectAll(text, customTerms) {
    const raw = [];

    function push(type, value, index) {
      raw.push({ type, value, index, length: value.length });
    }

    // Email — must run before UPI so email can later win the overlap check if needed
    for (const m of text.matchAll(new RegExp(RE_EMAIL.source, 'g'))) {
      push('email', m[0], m.index);
    }

    // UPI — specific VPA suffixes
    for (const m of text.matchAll(new RegExp(RE_UPI.source, 'g'))) {
      push('upi', m[0], m.index);
    }

    // Phone
    for (const m of text.matchAll(new RegExp(RE_PHONE.source, 'g'))) {
      if (countDigits(m[0]) >= PHONE_MIN_DIGITS) {
        push('phone', m[0], m.index);
      }
    }

    // IPv4
    for (const m of text.matchAll(new RegExp(RE_IPV4.source, 'g'))) {
      const [, a, b, c, d] = m;
      if ([a, b, c, d].every(o => parseInt(o, 10) <= 255)) {
        push('ipv4', m[0], m.index);
      }
    }

    // URL
    for (const m of text.matchAll(new RegExp(RE_URL.source, 'g'))) {
      push('url', m[0], m.index);
    }

    // Card (Luhn validated)
    for (const m of text.matchAll(new RegExp(RE_CARD.source, 'g'))) {
      if (luhnCheck(m[0])) {
        push('card', m[0], m.index);
      }
    }

    // Password disclosure
    for (const m of text.matchAll(new RegExp(RE_PASSWORD.source, 'gi'))) {
      // capture the value part (group 1); report its position within the full match
      const valueOffset = m[0].indexOf(m[1]);
      push('password', m[1], m.index + valueOffset);
    }

    // API key / token disclosure
    for (const m of text.matchAll(new RegExp(RE_API_KEY.source, 'gi'))) {
      const valueOffset = m[0].indexOf(m[1]);
      push('apiKey', m[1], m.index + valueOffset);
    }

    // OTP — only when nearby text has relevant wording
    for (const m of text.matchAll(new RegExp(RE_OTP_CODE.source, 'g'))) {
      const start = Math.max(0, m.index - OTP_WINDOW);
      const end   = Math.min(text.length, m.index + m[0].length + OTP_WINDOW);
      const window = text.slice(start, m.index) + text.slice(m.index + m[0].length, end);
      if (OTP_KEYWORDS.test(window)) {
        push('otp', m[0], m.index);
      }
    }

    // Long ID — will be filtered later to exclude already-matched card ranges
    for (const m of text.matchAll(new RegExp(RE_LONG_ID.source, 'g'))) {
      push('longId', m[0], m.index);
    }

    // Custom terms
    for (const term of (customTerms || [])) {
      const t = term.trim();
      if (!t) continue;
      const re = new RegExp(escapeRegex(t), 'gi');
      for (const m of text.matchAll(re)) {
        push('customTerm', m[0], m.index);
      }
    }

    return raw;
  }

  // ─── Overlap resolution ──────────────────────────────────────────────────────
  // Accepts raw detections; returns accepted list with no overlapping ranges.
  // Sort by index asc, then by priority asc (lower = higher priority).

  function resolveOverlaps(raw) {
    const priorityOf = type => {
      const i = OVERLAP_PRIORITY.indexOf(type);
      return i < 0 ? OVERLAP_PRIORITY.length : i;
    };

    // Sort: by index, break ties by priority (most sensitive first)
    const sorted = raw.slice().sort((a, b) => {
      if (a.index !== b.index) return a.index - b.index;
      return priorityOf(a.type) - priorityOf(b.type);
    });

    const accepted = [];

    for (const candidate of sorted) {
      const cEnd = candidate.index + candidate.length;
      const overlaps = accepted.some(a => {
        const aEnd = a.index + a.length;
        return candidate.index < aEnd && cEnd > a.index;
      });
      if (!overlaps) accepted.push(candidate);
    }

    return accepted;
  }

  // ─── Annotate detections ────────────────────────────────────────────────────
  // Adds category, label, placeholder to each accepted detection.

  function annotate(detections, context) {
    return detections.map(d => ({
      ...d,
      category:    CATEGORY_MAP[d.type],
      label:       getLabel(d.type, context),
      placeholder: PLACEHOLDERS[d.type],
    }));
  }

  // ─── Score ──────────────────────────────────────────────────────────────────

  function computeScore(detections, context) {
    const multiplier = CONTEXT_MULTIPLIER[context] || 1.0;
    const countByType = {};
    let neverTotal = 0;
    let softTotal  = 0;

    for (const d of detections) {
      const count = (countByType[d.type] = (countByType[d.type] || 0) + 1);
      const weight = LABEL_WEIGHT[d.label];
      const contribution = count === 1 ? weight : weight * 0.3;

      if (d.label === 'neverShare') {
        neverTotal += contribution;
      } else {
        softTotal += contribution;
      }
    }

    const raw = neverTotal + softTotal * multiplier;
    return Math.min(100, Math.round(raw));
  }

  function scoreBand(score) {
    if (score <= 20) return 'Minimal';
    if (score <= 40) return 'Low';
    if (score <= 60) return 'Moderate';
    if (score <= 80) return 'High';
    return 'Critical';
  }

  // ─── Exposure map ────────────────────────────────────────────────────────────
  // Each category: independent absolute 0–100, no cross-category normalisation.

  function computeExposureMap(detections) {
    const map = { Contact: 0, Authentication: 0, Financial: 0, Technical: 0, Identifiers: 0, Other: 0 };
    const countByCatType = {};

    for (const d of detections) {
      const key = d.category + '|' + d.type;
      const count = (countByCatType[key] = (countByCatType[key] || 0) + 1);
      const weight = LABEL_WEIGHT[d.label];
      const contribution = count === 1 ? weight : weight * 0.3;
      map[d.category] = Math.min(100, map[d.category] + contribution);
    }

    return map;
  }

  // ─── Clean text ──────────────────────────────────────────────────────────────
  // Replaces detection ranges according to redaction policy.
  // Builds result from character ranges — no repeated global replacement.

  const REDACT_LABELS = new Set(['neverShare', 'avoidSharing', 'reviewFirst']);

  function buildCleanText(text, detections) {
    // Collect ranges to redact, sorted by index
    const toRedact = detections
      .filter(d => REDACT_LABELS.has(d.label) || d.type === 'customTerm')
      .sort((a, b) => a.index - b.index);

    let result = '';
    let cursor = 0;

    for (const d of toRedact) {
      if (d.index < cursor) continue; // already consumed (shouldn't happen post-overlap-resolve)
      result += text.slice(cursor, d.index);
      result += d.placeholder;
      cursor = d.index + d.length;
    }

    result += text.slice(cursor);
    return result;
  }

  // ─── Privacy receipt ─────────────────────────────────────────────────────────

  function computeReceipt(detections) {
    const total    = detections.length;
    const redacted = detections.filter(d => REDACT_LABELS.has(d.label) || d.type === 'customTerm').length;
    const retained = detections.filter(d => d.label === 'likelyNeeded').length;
    const reductionPct = total === 0 ? 0 : Math.round((redacted / total) * 100);
    return { total, redacted, retained, reductionPct };
  }

  // ─── Public entry point ──────────────────────────────────────────────────────

  function analyzeText(text, context, customTerms) {
    const safeText    = typeof text    === 'string' ? text    : '';
    const safeContext = CONTEXT_ORDER.includes(context) ? context : 'publicPost';
    const safeTerms   = Array.isArray(customTerms) ? customTerms : [];

    if (!safeText.trim()) {
      return {
        detections:  [],
        score:       0,
        scoreBand:   'Minimal',
        exposureMap: { Contact: 0, Authentication: 0, Financial: 0, Technical: 0, Identifiers: 0, Other: 0 },
        cleanText:   '',
        receipt:     { total: 0, redacted: 0, retained: 0, reductionPct: 0 },
      };
    }

    const raw        = detectAll(safeText, safeTerms);
    const accepted   = resolveOverlaps(raw);
    const detections = annotate(accepted, safeContext);
    const score      = computeScore(detections, safeContext);
    const band       = scoreBand(score);
    const exposureMap = computeExposureMap(detections);
    const cleanText  = buildCleanText(safeText, detections);
    const receipt    = computeReceipt(detections);

    return { detections, score, scoreBand: band, exposureMap, cleanText, receipt };
  }

  // ─── Demo scenarios ──────────────────────────────────────────────────────────

  const DEMO_SCENARIOS = [
    {
      id:      'publicPost',
      label:   'Public Post',
      context: 'publicPost',
      text:
        "Just joined the Hillside Community Forum! Feel free to reach out — I'm at " +
        "prakash.menon92@mailhub.net or give me a call on +91 98201 34567. " +
        "Looking forward to connecting with everyone here.",
    },
    {
      id:      'aiChatbot',
      label:   'AI / Chatbot',
      context: 'aiChatbot',
      text:
        "Hey, I'm trying to debug why my API call keeps returning 403. " +
        "Here's my config — is something wrong with it?\n\n" +
        "api key: sk-demoXp92nTvqL8wKjR3mYcB5zAeF1hU0\n\n" +
        "The service is hosted at https://api.devtools-demo.io/v2/infer and I keep " +
        "getting a permission denied error.",
    },
    {
      id:      'customerSupport',
      label:   'Customer Support',
      context: 'customerSupport',
      text:
        "Hi, I'm writing about order #ORD-2024-88741. My registered email is " +
        "leena.varghese@quickmail.co. I tried to verify my identity but the " +
        "verification code I received was 819273 and it said invalid. " +
        "Please help me regain access to my account.",
    },
    {
      id:      'jobApplication',
      label:   'Job Application',
      context: 'jobApplication',
      text:
        "Dear Hiring Team,\n\n" +
        "I am writing to apply for the Junior Security Analyst position at Cortexify. " +
        "My name is Arjun Pillai and I can be reached at arjun.pillai@protonmail.com " +
        "or by phone at +91 77009 21438.\n\n" +
        "I hold a B.Tech in Computer Science and have completed internships focused on " +
        "network monitoring and vulnerability assessment. I look forward to discussing " +
        "how I can contribute to your team.",
    },
    {
      id:      'safeMessage',
      label:   'Safe Message',
      context: 'publicPost',
      text:
        "Had a great time at the workshop on sustainable packaging yesterday. " +
        "The session on material alternatives was really eye-opening. " +
        "Looking forward to the follow-up next month!",
    },
  ];

  // ─── Export namespace ────────────────────────────────────────────────────────

  window.MinimumShareRules = {
    analyzeText,
    DEMO_SCENARIOS,
    CONTEXT_LABELS,
    CATEGORY_MAP,
  };

}());
