// CyberShield Password Strength Analyzer & Security Lab Frontend

document.addEventListener('DOMContentLoaded', () => {
  initTabs();
  initAnalyzer();
  initGenerator();
  initDatabase();
  initCryptoLab();
});

// Toast notification helper
function showToast(message) {
  const toast = document.getElementById('toast');
  toast.textContent = message;
  toast.classList.add('show');
  setTimeout(() => {
    toast.classList.remove('show');
  }, 2500);
}

// Copy to clipboard helper
function copyToClipboard(text) {
  if (!text || text === 'Click Generate') return;
  navigator.clipboard.writeText(text).then(() => {
    showToast('Copied to clipboard!');
  }).catch(() => {
    // Fallback
    const tempInput = document.createElement('textarea');
    tempInput.value = text;
    document.body.appendChild(tempInput);
    tempInput.select();
    document.execCommand('copy');
    document.body.removeChild(tempInput);
    showToast('Copied to clipboard!');
  });
}

// Tab Switching
function initTabs() {
  const tabButtons = document.querySelectorAll('.nav-tab');
  const tabContents = document.querySelectorAll('.tab-content');

  tabButtons.forEach(btn => {
    btn.addEventListener('click', () => {
      const targetTabId = btn.getAttribute('data-tab');

      tabButtons.forEach(b => b.classList.remove('active'));
      tabContents.forEach(c => c.classList.remove('active'));

      btn.classList.add('active');
      const targetContent = document.getElementById(targetTabId);
      if (targetContent) {
        targetContent.classList.add('active');
      }

      // Auto-trigger tab specific actions if needed
      if (targetTabId === 'tab-database') {
        loadUserHistory();
      } else if (targetTabId === 'tab-crypto') {
        runCryptoDemo();
      }
    });
  });
}

function switchToAnalyzerWithPassword(password) {
  const tabBtn = document.querySelector('.nav-tab[data-tab="tab-analyzer"]');
  if (tabBtn) tabBtn.click();

  const analyzerInput = document.getElementById('analyzer-input');
  if (analyzerInput) {
    analyzerInput.value = password;
    analyzerInput.type = 'text'; // Make it visible when analyzing generated password
    updateEyeIcon(true);
    analyzeCurrentPassword();
    analyzerInput.scrollIntoView({ behavior: 'smooth' });
  }
}

function updateEyeIcon(isVisible) {
  const eyeIcon = document.getElementById('eye-icon');
  if (!eyeIcon) return;
  if (isVisible) {
    eyeIcon.innerHTML = `
      <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"></path>
      <line x1="1" y1="1" x2="23" y2="23"></line>
    `;
  } else {
    eyeIcon.innerHTML = `
      <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path>
      <circle cx="12" cy="12" r="3"></circle>
    `;
  }
}

/* ==========================================================================
   TAB 1: STRENGTH ANALYZER
   ========================================================================== */
function initAnalyzer() {
  const input = document.getElementById('analyzer-input');
  const toggleBtn = document.getElementById('toggle-password-btn');
  const clearBtn = document.getElementById('clear-analyzer-btn');

  let debounceTimer = null;
  input.addEventListener('input', () => {
    clearTimeout(debounceTimer);
    debounceTimer = setTimeout(analyzeCurrentPassword, 80);
  });

  toggleBtn.addEventListener('click', () => {
    const isPass = input.type === 'password';
    input.type = isPass ? 'text' : 'password';
    updateEyeIcon(isPass);
  });

  clearBtn.addEventListener('click', () => {
    input.value = '';
    analyzeCurrentPassword();
  });

  // Initial call with empty state
  analyzeCurrentPassword();
}

async function analyzeCurrentPassword() {
  const password = document.getElementById('analyzer-input').value;

  try {
    const res = await fetch('/api/analyze', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ password })
    });

    if (!res.ok) throw new Error('API error');
    const data = await res.json();
    renderAnalysisResults(data);
  } catch (err) {
    console.error('Analysis error:', err);
  }
}

function renderAnalysisResults(data) {
  // Score and Meter
  const scoreText = document.getElementById('meter-score-text');
  const ratingBadge = document.getElementById('rating-badge');
  const progressFill = document.getElementById('progress-fill');

  scoreText.textContent = `${data.score}%`;
  ratingBadge.textContent = data.rating;
  ratingBadge.className = `badge ${data.ratingClass}`;

  progressFill.style.width = `${data.score}%`;
  progressFill.className = `progress-fill ${data.ratingClass}`;

  // Metrics
  document.getElementById('metric-length').textContent = data.length;
  document.getElementById('metric-pool').textContent = data.charPoolSize;
  document.getElementById('metric-entropy').innerHTML = `${data.entropyBits} <small>bits</small>`;
  document.getElementById('metric-shannon').innerHTML = `${data.shannonBits} <small>bits</small>`;

  // Crack Times
  document.getElementById('crack-online-throttled').textContent = data.crackTimes.onlineThrottled;
  document.getElementById('crack-online-unthrottled').textContent = data.crackTimes.onlineUnthrottled;
  document.getElementById('crack-offline-slow').textContent = data.crackTimes.offlineSlowHash;
  document.getElementById('crack-offline-fast').textContent = data.crackTimes.offlineFastHash;

  // Checklist
  setChecklistItem('chk-min-len', data.checks.hasMinLength);
  setChecklistItem('chk-opt-len', data.checks.hasOptimalLength);
  setChecklistItem('chk-lowercase', data.checks.hasLowercase);
  setChecklistItem('chk-uppercase', data.checks.hasUppercase);
  setChecklistItem('chk-numbers', data.checks.hasNumbers);
  setChecklistItem('chk-symbols', data.checks.hasSymbols);
  setChecklistItem('chk-no-repeats', data.checks.noRepeats);
  setChecklistItem('chk-no-sequences', data.checks.noSequences);
  setChecklistItem('chk-no-walks', data.checks.noKeyboardWalks);
  setChecklistItem('chk-no-dict', data.checks.noDictionaryMatch);

  // Vulnerabilities & Recommendations
  const vulnList = document.getElementById('vulnerabilities-list');
  vulnList.innerHTML = '';
  if (data.vulnerabilities && data.vulnerabilities.length > 0) {
    data.vulnerabilities.forEach(v => {
      const li = document.createElement('li');
      li.textContent = v;
      vulnList.appendChild(li);
    });
  } else {
    const li = document.createElement('li');
    li.textContent = 'None detected! Password exhibits high resilience.';
    vulnList.appendChild(li);
  }

  const recList = document.getElementById('recommendations-list');
  recList.innerHTML = '';
  if (data.recommendations && data.recommendations.length > 0) {
    data.recommendations.forEach(r => {
      const li = document.createElement('li');
      li.textContent = r;
      recList.appendChild(li);
    });
  }

  // Suggestions
  renderSuggestions(data.suggestions || []);
}

function setChecklistItem(elementId, passed) {
  const el = document.getElementById(elementId);
  if (!el) return;
  el.classList.remove('passed', 'failed');
  el.classList.add(passed ? 'passed' : 'failed');
}

function renderSuggestions(suggestions) {
  const container = document.getElementById('smart-suggestions-container');
  container.innerHTML = '';

  if (suggestions.length === 0) {
    container.innerHTML = '<p class="text-muted">Type in a password to generate contextual alternatives.</p>';
    return;
  }

  suggestions.forEach(item => {
    const card = document.createElement('div');
    card.className = 'suggestion-item';

    card.innerHTML = `
      <div>
        <div class="sugg-header">${item.label}</div>
        <div class="sugg-desc">${item.description}</div>
      </div>
      <div class="sugg-pwd-box">
        <span class="sugg-pwd-text">${escapeHtml(item.password)}</span>
        <div class="sugg-actions">
          <button class="icon-button copy-sugg-btn" title="Copy to clipboard">
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>
          </button>
          <button class="primary-btn-sm test-sugg-btn" title="Analyze this alternative">Analyze</button>
        </div>
      </div>
    `;

    card.querySelector('.copy-sugg-btn').addEventListener('click', () => {
      copyToClipboard(item.password);
    });

    card.querySelector('.test-sugg-btn').addEventListener('click', () => {
      switchToAnalyzerWithPassword(item.password);
    });

    container.appendChild(card);
  });
}

function escapeHtml(str) {
  return (str || '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

/* ==========================================================================
   TAB 2: PASSWORD & PASSPHRASE GENERATOR
   ========================================================================== */
function initGenerator() {
  // Random Password Generator Controls
  const lenSlider = document.getElementById('pwd-len-slider');
  const lenVal = document.getElementById('pwd-len-val');
  const optUpper = document.getElementById('opt-upper');
  const optLower = document.getElementById('opt-lower');
  const optNumbers = document.getElementById('opt-numbers');
  const optSymbols = document.getElementById('opt-symbols');
  const optAmbiguous = document.getElementById('opt-ambiguous');
  const genRandomBtn = document.getElementById('generate-random-btn');
  const genPwdDisplay = document.getElementById('gen-password-display');
  const copyGenPwdBtn = document.getElementById('copy-gen-pwd-btn');
  const testGenPwdBtn = document.getElementById('test-gen-pwd-btn');

  lenSlider.addEventListener('input', () => {
    lenVal.textContent = lenSlider.value;
  });

  async function generateRandom() {
    try {
      const res = await fetch('/api/generate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          type: 'random',
          length: parseInt(lenSlider.value, 10),
          includeUpper: optUpper.checked,
          includeLower: optLower.checked,
          includeNumbers: optNumbers.checked,
          includeSymbols: optSymbols.checked,
          excludeAmbiguous: optAmbiguous.checked
        })
      });
      const data = await res.json();
      genPwdDisplay.textContent = data.password;
    } catch (err) {
      console.error('Random generator error:', err);
    }
  }

  genRandomBtn.addEventListener('click', generateRandom);
  copyGenPwdBtn.addEventListener('click', () => copyToClipboard(genPwdDisplay.textContent));
  testGenPwdBtn.addEventListener('click', () => switchToAnalyzerWithPassword(genPwdDisplay.textContent));

  // Diceware Passphrase Generator Controls
  const phraseSlider = document.getElementById('phrase-count-slider');
  const phraseVal = document.getElementById('phrase-count-val');
  const phraseSep = document.getElementById('phrase-sep');
  const phraseNum = document.getElementById('phrase-num');
  const phraseSym = document.getElementById('phrase-sym');
  const genPhraseBtn = document.getElementById('generate-phrase-btn');
  const genPhraseDisplay = document.getElementById('gen-passphrase-display');
  const copyGenPhraseBtn = document.getElementById('copy-gen-phrase-btn');
  const testGenPhraseBtn = document.getElementById('test-gen-phrase-btn');

  phraseSlider.addEventListener('input', () => {
    phraseVal.textContent = `${phraseSlider.value} Words`;
  });

  async function generatePhrase() {
    try {
      const res = await fetch('/api/generate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          type: 'passphrase',
          wordCount: parseInt(phraseSlider.value, 10),
          separator: phraseSep.value,
          capitalize: true,
          includeNumber: phraseNum.checked,
          includeSymbol: phraseSym.checked
        })
      });
      const data = await res.json();
      genPhraseDisplay.textContent = data.password;
    } catch (err) {
      console.error('Passphrase generator error:', err);
    }
  }

  genPhraseBtn.addEventListener('click', generatePhrase);
  copyGenPhraseBtn.addEventListener('click', () => copyToClipboard(genPhraseDisplay.textContent));
  testGenPhraseBtn.addEventListener('click', () => switchToAnalyzerWithPassword(genPhraseDisplay.textContent));

  // Pre-generate samples on load
  generateRandom();
  generatePhrase();
}

/* ==========================================================================
   TAB 3: DATABASE & REUSE PREVENTOR
   ========================================================================== */
function initDatabase() {
  const usernameInput = document.getElementById('db-username');
  const passwordInput = document.getElementById('db-password');
  const saveBtn = document.getElementById('save-password-btn');
  const refreshBtn = document.getElementById('refresh-history-btn');

  saveBtn.addEventListener('click', async () => {
    const username = usernameInput.value.trim();
    const password = passwordInput.value;

    if (!username) {
      showDbAlert('danger', 'Please enter a username or account identifier.');
      return;
    }
    if (!password) {
      showDbAlert('danger', 'Please enter a candidate password.');
      return;
    }

    try {
      const res = await fetch('/api/save-password', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password })
      });

      const data = await res.json();

      if (res.ok && data.success) {
        showDbAlert('success', `✔ ${data.message}`);
        passwordInput.value = '';
        loadUserHistory();
      } else {
        showDbAlert('danger', `✖ ${data.message || 'Error saving password.'}`);
      }
    } catch (err) {
      showDbAlert('danger', 'Network or server error while checking database.');
    }
  });

  refreshBtn.addEventListener('click', loadUserHistory);
  usernameInput.addEventListener('change', loadUserHistory);
}

function showDbAlert(type, message) {
  const alertBox = document.getElementById('db-alert-box');
  const alertMsg = document.getElementById('db-alert-message');
  alertBox.className = `alert-box ${type}`;
  alertMsg.textContent = message;
}

async function loadUserHistory() {
  const username = document.getElementById('db-username').value.trim();
  const tableBody = document.getElementById('history-table-body');
  if (!username) return;

  try {
    const res = await fetch(`/api/history/${encodeURIComponent(username)}`);
    const data = await res.json();

    tableBody.innerHTML = '';
    if (!data.history || data.history.length === 0) {
      tableBody.innerHTML = `
        <tr>
          <td colspan="6" class="text-center text-muted">No password history found for "${escapeHtml(username)}". Set a password to start tracking.</td>
        </tr>
      `;
      return;
    }

    data.history.forEach((row, index) => {
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td>${index + 1}</td>
        <td><span class="badge strong">${escapeHtml(row.algorithm)} (${row.iterations.toLocaleString()} iters)</span></td>
        <td><span class="font-mono" style="font-size:0.8rem">${escapeHtml(row.masked_salt)}</span></td>
        <td><span class="font-mono" style="font-size:0.8rem; color:#a5f3fc;">${escapeHtml(row.masked_hash)}</span></td>
        <td>${escapeHtml(row.created_at)}</td>
        <td><span class="badge very-strong">Active Salted Hash</span></td>
      `;
      tableBody.appendChild(tr);
    });
  } catch (err) {
    console.error('Error fetching history:', err);
  }
}

/* ==========================================================================
   TAB 4: CRYPTOGRAPHY & SECURITY LAB
   ========================================================================== */
function initCryptoLab() {
  const btn = document.getElementById('run-crypto-demo-btn');
  const input = document.getElementById('crypto-test-input');

  btn.addEventListener('click', runCryptoDemo);
  input.addEventListener('keypress', (e) => {
    if (e.key === 'Enter') runCryptoDemo();
  });
}

async function runCryptoDemo() {
  const text = document.getElementById('crypto-test-input').value;
  const container = document.getElementById('crypto-results-container');

  try {
    const res = await fetch('/api/crypto-demo', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ text })
    });
    const data = await res.json();

    container.innerHTML = '';

    // First card: Base64 Encoding
    const encCard = document.createElement('div');
    encCard.className = 'crypto-card';
    encCard.innerHTML = `
      <div>
        <div class="crypto-card-head">
          <span class="crypto-card-title">${data.encoding.algorithm} (Reversible)</span>
          <span class="badge very-weak">NOT A HASH</span>
        </div>
        <div class="hash-output-box">${escapeHtml(data.encoding.value)}</div>
      </div>
      <div>
        <p class="crypto-card-note">${data.encoding.note}</p>
        <p class="crypto-card-note" style="color:#60a5fa; margin-top:0.3rem;">Decodes back to: <code>"${escapeHtml(data.encoding.reversibleOutput)}"</code></p>
      </div>
    `;
    container.appendChild(encCard);

    // Hash cards
    data.hashes.forEach(item => {
      const card = document.createElement('div');
      card.className = 'crypto-card';

      let badgeClass = 'very-weak';
      if (item.algorithm.includes('PBKDF2')) badgeClass = 'very-strong';
      else if (item.salt !== 'None') badgeClass = 'moderate';
      else badgeClass = 'weak';

      card.innerHTML = `
        <div>
          <div class="crypto-card-head">
            <span class="crypto-card-title">${escapeHtml(item.algorithm)}</span>
            <span class="badge ${badgeClass}">${escapeHtml(item.type)}</span>
          </div>
          <div class="hash-output-box">${escapeHtml(item.hash)}</div>
        </div>
        <div>
          <p class="crypto-card-note"><strong>Salt:</strong> ${escapeHtml(item.salt)}</p>
          <p class="crypto-card-note" style="margin-top:0.3rem;">${escapeHtml(item.vulnerabilities)}</p>
        </div>
      `;
      container.appendChild(card);
    });
  } catch (err) {
    console.error('Crypto demo error:', err);
  }
}
