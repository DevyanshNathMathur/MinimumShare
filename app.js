// MinimumShare — app.js
// UI wiring, rendering, and interaction logic.

(function () {

  // ─── Engine guard ────────────────────────────────────────────────────────────

  if (!window.MinimumShareRules) {
    console.error('MinimumShare: rules engine not available.');
    return;
  }

  const { analyzeText, DEMO_SCENARIOS, CONTEXT_LABELS } = window.MinimumShareRules;

  // ─── DOM refs ────────────────────────────────────────────────────────────────

  const elContext       = document.getElementById('sharing-context');
  const elText          = document.getElementById('user-text');
  const elTerms         = document.getElementById('custom-terms');
  const elCheckBtn      = document.getElementById('check-btn');
  const elValidation    = document.getElementById('validation-message');
  const elResults       = document.getElementById('results');

  const elScoreDisplay  = document.getElementById('score-display');
  const elScoreValue    = document.getElementById('score-value');
  const elScoreBand     = document.getElementById('score-band-label');
  const elScoreCtx      = document.getElementById('score-context-label');
  const elRingFill      = document.querySelector('#score-ring .ring-fill');

  const elReceiptTotal      = document.querySelector('#receipt-total .receipt-number');
  const elReceiptRedacted   = document.querySelector('#receipt-redacted .receipt-number');
  const elReceiptRetained   = document.querySelector('#receipt-retained .receipt-number');
  const elReceiptReduction  = document.querySelector('#receipt-reduction .receipt-number');

  const MAP_BARS = {
    Contact:        document.getElementById('map-bar-contact'),
    Authentication: document.getElementById('map-bar-authentication'),
    Financial:      document.getElementById('map-bar-financial'),
    Technical:      document.getElementById('map-bar-technical'),
    Identifiers:    document.getElementById('map-bar-identifiers'),
    Other:          document.getElementById('map-bar-other'),
  };
  const MAP_VALS = {
    Contact:        document.getElementById('map-val-contact'),
    Authentication: document.getElementById('map-val-authentication'),
    Financial:      document.getElementById('map-val-financial'),
    Technical:      document.getElementById('map-val-technical'),
    Identifiers:    document.getElementById('map-val-identifiers'),
    Other:          document.getElementById('map-val-other'),
  };

  const elDetectionList   = document.getElementById('detection-list');
  const elSafeReview      = document.getElementById('safe-review-output');
  const elCleanOutput     = document.getElementById('clean-version-output');
  const elCopyBtn         = document.getElementById('copy-clean-btn');

  // ─── Constants ───────────────────────────────────────────────────────────────

  const RING_CIRCUMFERENCE = 264;

  const BAND_CLASSES = ['band-minimal', 'band-low', 'band-moderate', 'band-high', 'band-critical'];

  const TYPE_LABELS = {
    email:      'Email',
    phone:      'Phone',
    otp:        'Verification code',
    upi:        'UPI ID',
    card:       'Payment card',
    password:   'Password',
    apiKey:     'API key / token',
    ipv4:       'IP address',
    url:        'URL',
    longId:     'Possible identification number',
    customTerm: 'Protected term',
  };

  const CHIP_LABELS = {
    neverShare:   'Never Share',
    avoidSharing: 'Avoid Sharing',
    reviewFirst:  'Review First',
    likelyNeeded: 'Likely Needed',
  };

  const CHIP_CLASSES = {
    neverShare:   'never',
    avoidSharing: 'avoid',
    reviewFirst:  'review',
    likelyNeeded: 'needed',
  };

  const BADGE_SHORT = {
    Contact:        'Contact',
    Authentication: 'Auth',
    Financial:      'Finance',
    Technical:      'Technical',
    Identifiers:    'ID',
    Other:          'Other',
  };

  const CONTEXT_SUMMARY = {
    publicPost:      'Public sharing can expose information to a broad audience.',
    aiChatbot:       'Review sensitive information before submitting it to an AI service.',
    unknownPerson:   'Limit personal information when communicating with someone you do not know.',
    customerSupport: 'Share only information genuinely needed to resolve the issue.',
    jobApplication:  'Professional contact details may be expected, but unrelated sensitive data should be removed.',
  };

  // High-risk types whose values are masked aggressively
  const MASK_FULLY = new Set(['otp', 'password', 'card', 'apiKey', 'customTerm']);

  // ─── Reduced-motion helper ────────────────────────────────────────────────────

  function prefersReducedMotion() {
    return window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  }

  // ─── Value masking ────────────────────────────────────────────────────────────

  function maskValue(type, value) {
    if (MASK_FULLY.has(type)) {
      return '•'.repeat(Math.min(value.length, 8));
    }
    if (type === 'email') {
      const at = value.indexOf('@');
      if (at > 1) return value[0] + '***' + value.slice(at);
      return '***' + value.slice(at);
    }
    if (type === 'phone') {
      const digits = value.replace(/\D/g, '');
      return value.slice(0, value.length - 4).replace(/\d/g, '•') + digits.slice(-4);
    }
    // url, ipv4, longId — readable but trimmed if very long
    if (value.length > 60) return value.slice(0, 57) + '…';
    return value;
  }

  // ─── Score rendering ──────────────────────────────────────────────────────────

  function renderScore(score, band, context) {
    elScoreValue.textContent = score;
    elScoreBand.textContent  = band;

    BAND_CLASSES.forEach(c => elScoreDisplay.classList.remove(c));
    elScoreDisplay.classList.add('band-' + band.toLowerCase());

    const offset = RING_CIRCUMFERENCE - (score / 100) * RING_CIRCUMFERENCE;
    elRingFill.style.strokeDashoffset = offset;

    elScoreCtx.textContent = CONTEXT_SUMMARY[context] || '';
  }

  // ─── Receipt rendering ────────────────────────────────────────────────────────

  function renderReceipt(receipt) {
    elReceiptTotal.textContent     = receipt.total;
    elReceiptRedacted.textContent  = receipt.redacted;
    elReceiptRetained.textContent  = receipt.retained;
    elReceiptReduction.textContent = receipt.reductionPct + '%';
  }

  // ─── Exposure map rendering ───────────────────────────────────────────────────

  function renderMap(exposureMap) {
    for (const [category, bar] of Object.entries(MAP_BARS)) {
      const raw   = exposureMap[category] || 0;
      const value = Math.max(0, Math.min(100, Math.round(raw)));
      bar.style.setProperty('--bar-pct', value + '%');
      MAP_VALS[category].textContent = value + '%';
    }
  }

  // ─── Detection list rendering ─────────────────────────────────────────────────

  function renderDetectionList(detections) {
    elDetectionList.textContent = '';

    if (detections.length === 0) {
      const li = document.createElement('li');
      li.className = 'detection-empty';
      li.textContent = 'No common sensitive-data patterns were detected in this text.';
      elDetectionList.appendChild(li);
      return;
    }

    for (const d of detections) {
      const li = document.createElement('li');
      li.className = 'detection-item';

      // Left severity bar
      const bar = document.createElement('span');
      bar.className = 'detection-severity-bar ' + (CHIP_CLASSES[d.label] || '');
      bar.setAttribute('aria-hidden', 'true');
      li.appendChild(bar);

      // Content wrapper (type + value)
      const content = document.createElement('span');
      content.className = 'detection-content';

      const typeEl = document.createElement('span');
      typeEl.className = 'detection-type';
      typeEl.textContent = TYPE_LABELS[d.type] || d.type;
      content.appendChild(typeEl);

      const valEl = document.createElement('span');
      valEl.className = 'detection-value';
      valEl.textContent = maskValue(d.type, d.value);
      content.appendChild(valEl);

      li.appendChild(content);

      // Recommendation chip
      const chip = document.createElement('span');
      chip.className = 'label-chip ' + (CHIP_CLASSES[d.label] || '');
      chip.textContent = CHIP_LABELS[d.label] || d.label;
      li.appendChild(chip);

      // Category
      const cat = document.createElement('span');
      cat.className = 'detection-category';
      cat.textContent = d.category;
      li.appendChild(cat);

      elDetectionList.appendChild(li);
    }
  }

  // ─── Safe review rendering ────────────────────────────────────────────────────
  // DOM-node construction only — user text never touches innerHTML.

  function renderSafeReview(text, detections) {
    elSafeReview.textContent = '';

    if (detections.length === 0) {
      elSafeReview.textContent = text;
      return;
    }

    const sorted = detections.slice().sort((a, b) => a.index - b.index);
    const frag   = document.createDocumentFragment();
    let cursor   = 0;

    for (const d of sorted) {
      if (d.index < cursor) continue;

      // Plain text before this detection
      if (d.index > cursor) {
        frag.appendChild(document.createTextNode(text.slice(cursor, d.index)));
      }

      // Highlighted detection span
      const mark = document.createElement('mark');
      mark.dataset.label    = d.label;
      mark.dataset.category = d.category;
      mark.appendChild(document.createTextNode(text.slice(d.index, d.index + d.length)));

      const badge = document.createElement('span');
      badge.className   = 'badge';
      badge.textContent = BADGE_SHORT[d.category] || d.category;
      mark.appendChild(badge);

      frag.appendChild(mark);
      cursor = d.index + d.length;
    }

    // Remaining plain text after last detection
    if (cursor < text.length) {
      frag.appendChild(document.createTextNode(text.slice(cursor)));
    }

    elSafeReview.appendChild(frag);
  }

  // ─── Clean version rendering ──────────────────────────────────────────────────

  function renderCleanVersion(cleanText) {
    elCleanOutput.textContent = cleanText;
  }

  // ─── Reset result view ────────────────────────────────────────────────────────

  function resetResultsView() {
    elResults.classList.add('hidden');

    elScoreValue.textContent = '—';
    elScoreBand.textContent  = '—';
    BAND_CLASSES.forEach(c => elScoreDisplay.classList.remove(c));
    elRingFill.style.strokeDashoffset = RING_CIRCUMFERENCE;
    elScoreCtx.textContent = 'Run an analysis to see your exposure score.';

    elReceiptTotal.textContent    = '—';
    elReceiptRedacted.textContent = '—';
    elReceiptRetained.textContent = '—';
    elReceiptReduction.textContent = '—';

    for (const [category, bar] of Object.entries(MAP_BARS)) {
      bar.style.setProperty('--bar-pct', '0%');
      MAP_VALS[category].textContent = '0';
    }

    elDetectionList.textContent = '';
    elSafeReview.textContent    = '';
    elCleanOutput.textContent   = '';
  }

  // ─── Validation ───────────────────────────────────────────────────────────────

  function showValidation(msg) {
    elValidation.textContent = msg;
    elValidation.classList.remove('hidden');
  }

  function clearValidation() {
    elValidation.textContent = '';
    elValidation.classList.add('hidden');
  }

  // ─── Run analysis ─────────────────────────────────────────────────────────────

  function runAnalysis() {
    const text    = elText.value;
    const context = elContext.value;
    const terms   = elTerms.value
      .split(',')
      .map(t => t.trim())
      .filter(t => t.length > 0);

    if (!text.trim()) {
      showValidation('Enter some text to review before continuing.');
      elText.focus();
      return;
    }

    clearValidation();

    const result = analyzeText(text, context, terms);

    renderScore(result.score, result.scoreBand, context);
    renderReceipt(result.receipt);
    renderMap(result.exposureMap);
    renderDetectionList(result.detections);
    renderSafeReview(text, result.detections);
    renderCleanVersion(result.cleanText);

    // Store clean text for copy button
    elCopyBtn.dataset.clean = result.cleanText;

    elResults.classList.remove('hidden');

    elResults.scrollIntoView({
      behavior: prefersReducedMotion() ? 'auto' : 'smooth',
      block: 'start',
    });
  }

  // ─── Copy clean version ───────────────────────────────────────────────────────

  function copyCleanVersion() {
    const clean = elCopyBtn.dataset.clean || '';

    function showCopied() {
      elCopyBtn.textContent = 'Copied!';
      setTimeout(() => { elCopyBtn.textContent = 'Copy Clean Version'; }, 1500);
    }

    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(clean).then(showCopied).catch(() => fallbackCopy(clean, showCopied));
    } else {
      fallbackCopy(clean, showCopied);
    }
  }

  function fallbackCopy(text, callback) {
    const ta = document.createElement('textarea');
    ta.value = text;
    ta.setAttribute('readonly', '');
    ta.style.cssText = 'position:absolute;left:-9999px;top:-9999px;';
    document.body.appendChild(ta);
    ta.select();
    try { document.execCommand('copy'); callback(); } catch (_) { /* silent */ }
    document.body.removeChild(ta);
  }

  // ─── Load demo scenario ────────────────────────────────────────────────────────

  function loadDemo(demoId) {
    const scenario = DEMO_SCENARIOS.find(s => s.id === demoId);
    if (!scenario) return;

    elContext.value = scenario.context;
    elText.value    = scenario.text;
    elTerms.value   = '';
    clearValidation();
    resetResultsView();
    elText.focus();
  }

  // ─── Context hint update ──────────────────────────────────────────────────────
  // Keeps the context-panel hint text in sync with the selected context.

  const elContextHint = document.getElementById('context-hint-text');

  const CONTEXT_HINTS = {
    publicPost:      'A public post can be seen by anyone. Even seemingly harmless details can be combined to identify you.',
    aiChatbot:       'AI services may store or use submitted content for training. Avoid sharing credentials or personal data.',
    unknownPerson:   'You cannot verify who will read this message. Share only what is strictly necessary.',
    customerSupport: 'Support agents need enough information to help you, but not unrelated personal or financial details.',
    jobApplication:  'Contact information is expected, but medical history, identification numbers, and credentials are not.',
  };

  function updateContextHint() {
    if (!elContextHint) return;
    const p = elContextHint.querySelector('p');
    if (p) p.textContent = CONTEXT_HINTS[elContext.value] || '';
  }

  // ─── Event wiring ─────────────────────────────────────────────────────────────

  elCheckBtn.addEventListener('click', runAnalysis);

  elCopyBtn.addEventListener('click', copyCleanVersion);

  elContext.addEventListener('change', updateContextHint);

  document.querySelectorAll('.btn-demo').forEach(btn => {
    btn.addEventListener('click', () => loadDemo(btn.dataset.demo));
  });

  // ─── Initialise ───────────────────────────────────────────────────────────────

  updateContextHint();

}());
