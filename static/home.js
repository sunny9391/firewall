'use strict';

/* ── Feature name mapping ────────────────────────────────────────── */
const FEATURE_LABELS = {
  URI_Length:          'URI Length',
  GET_Length:          'GET Data Length',
  POST_Length:         'POST Data Length',
  URI_Entropy:         'URI Entropy',
  GET_Entropy:         'GET Entropy',
  POST_Entropy:        'POST Entropy',
  Numeric_Text_Ratio:  'Numeric/Text Ratio',
  Special_Char_Count:  'Special Chars',
  URL_Encoded_Count:   'URL-Encoded Seqs',
  Keyword_Count:       'Attack Keywords',
};

/* ── Utility ─────────────────────────────────────────────────────── */
const $ = id => document.getElementById(id);
const esc = s => String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');

/* ── Render ML feature table ─────────────────────────────────────── */
function renderFeatures(features) {
  if (!features || typeof features !== 'object') return '';
  const rows = Object.entries(features).map(([k, v]) => {
    const label = FEATURE_LABELS[k] || k;
    const val   = typeof v === 'number' ? (Number.isInteger(v) ? v : v.toFixed(4)) : v;
    return `<tr><td class="feat-key">${label}</td><td class="feat-val">${val}</td></tr>`;
  }).join('');
  return `
    <div class="features-section">
      <div class="features-toggle" onclick="this.closest('.features-section').classList.toggle('open')">
        <span>▸ ML Feature Vector</span>
      </div>
      <div class="features-body">
        <table class="feat-table"><tbody>${rows}</tbody></table>
      </div>
    </div>`;
}

/* ── Render result box ───────────────────────────────────────────── */
function renderResult(data) {
  const resultDiv = $('result');
  const status = data.status || 'unknown';

  let icon, cls, headline, sub, extra = '';

  if (status === 'malicious') {
    icon = '🔴'; cls = 'danger';
    headline = data.message || 'Threat Detected';
    sub = 'This request matches a known attack signature and has been blocked.';
  } else if (status === 'valid') {
    icon = '🟢'; cls = 'success';
    headline = data.message || 'Request is Safe';
    sub = data.reason === 'ml'
      ? (data.ml_verdict || 'AI scan complete — no threats found.')
      : 'Passed all signature checks.';
    extra = renderFeatures(data.features);
  } else if (status === 'suspicious') {
    icon = '🟠'; cls = 'warning';
    headline = data.message || 'Suspicious Request';
    sub = 'Obfuscated patterns detected. ML model unavailable for deep analysis.';
    extra = renderFeatures(data.features);
  } else if (status === 'blocked') {
    icon = '🚦'; cls = 'ratelimit';
    headline = data.message || 'Rate Limited';
    sub = 'Too many requests from your IP. Please wait before trying again.';
  } else {
    icon = '🟡'; cls = 'warning';
    headline = data.ml_verdict || data.message || 'Analysis Complete';
    sub = 'AI analysis complete.';
    extra = renderFeatures(data.features);
  }

  const reasonTag = data.reason
    ? `<span class="result-reason-tag">${data.reason.toUpperCase()}</span>`
    : '';

  resultDiv.innerHTML = `
    <div class="result-box ${cls}">
      <div class="result-left">
        <span class="result-icon">${icon}</span>
      </div>
      <div class="result-right">
        <div class="result-headline">${esc(headline)} ${reasonTag}</div>
        <div class="result-sub">${esc(sub)}</div>
        ${extra}
      </div>
    </div>`;
}

/* ── Submit handler ─────────────────────────────────────────────── */
$('submit-btn')?.addEventListener('click', async () => {
  const input     = $('user-input');
  const resultDiv = $('result');
  const loading   = $('loading');
  const userInput = input?.value?.trim() || '';

  if (!userInput) {
    input.classList.add('shake');
    setTimeout(() => input.classList.remove('shake'), 500);
    return;
  }

  loading.style.display = 'flex';
  resultDiv.innerHTML   = '';

  try {
    const res  = await fetch('/check_request', {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ user_request: userInput }),
    });
    const data = await res.json();
    loading.style.display = 'none';
    renderResult(data);
  } catch (err) {
    loading.style.display = 'none';
    resultDiv.innerHTML = `
      <div class="result-box danger">
        <div class="result-left"><span class="result-icon">⚠️</span></div>
        <div class="result-right">
          <div class="result-headline">Connection Error</div>
          <div class="result-sub">Could not reach the server. Please try again.</div>
        </div>
      </div>`;
  }
});

/* Enter key support */
$('user-input')?.addEventListener('keydown', e => {
  if (e.key === 'Enter') $('submit-btn')?.click();
});

/* ── Security tips carousel ─────────────────────────────────────── */
document.addEventListener('DOMContentLoaded', () => {
  const slides = document.querySelectorAll('.tip-slide');
  let current = 0;

  function show(idx) {
    slides.forEach((s, i) => s.classList.toggle('active', i === idx));
  }

  document.querySelector('.tip-nav-btn.prev')?.addEventListener('click', () => {
    current = (current === 0 ? slides.length - 1 : current - 1);
    show(current);
  });
  document.querySelector('.tip-nav-btn.next')?.addEventListener('click', () => {
    current = (current === slides.length - 1 ? 0 : current + 1);
    show(current);
  });

  // Auto-advance every 6 s
  setInterval(() => {
    current = (current === slides.length - 1 ? 0 : current + 1);
    show(current);
  }, 6000);

  show(0);
});