'use strict';

// ======= DOM =======
const el = (id) => document.getElementById(id);
const lengthEl = el('length');
const countEl = el('count');
const uppercaseEl = el('uppercase');
const lowercaseEl = el('lowercase');
const digitsEl = el('digits');
const symbolsEl = el('symbols');
const enforceClassesEl = el('enforce-classes');

const entropyBitsEl = el('entropy-bits');
const charsetSizeEl = el('charset-size');
const entropyMeterEl = el('entropy-meter');
const entropyNoteEl = el('entropy-note');

const validationEl = el('validation');
const generateBtn = el('generate');

const resultsCard = el('results');
const listEl = el('list');
const savedControls = el('saved-controls');
const downloadAllBtn = el('download-all');
const clearSavedBtn = el('clear-saved');
const savedCountEl = el('saved-count');

const toastEl = el('toast');

// ======= CONSTANTS =======
const CHARSETS = {
  uppercase: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
  lowercase: 'abcdefghijklmnopqrstuvwxyz',
  digits: '0123456789',
  symbols: '!@#$%^&*()_+-=[]{}|;:,.<>?/~'
};

const LIMITS = {
  minLen: 4,
  maxLen: 128,
  minCount: 1,
  maxCount: 200,
  maxTotalChars: 60000 // DoS guard (length * count)
};

// ======= UTIL =======
function showToast(message, ms = 2200) {
  toastEl.textContent = message;
  toastEl.classList.add('show');
  if (ms > 0) {
    setTimeout(() => toastEl.classList.remove('show'), ms);
  }
}

function calcEntropyBits(length, charsetSize) {
  if (!length || !charsetSize) return 0;
  // entropy = length * log2(charsetSize)
  return length * Math.log2(charsetSize);
}

function updateEntropy() {
  const { valid, charset, message } = validate(true);
  if (!valid) {
    entropyBitsEl.textContent = '—';
    charsetSizeEl.textContent = '(charset size: —)';
    entropyMeterEl.style.width = '0%';
    entropyNoteEl.textContent = message || 'Adjust options to compute entropy.';
    return;
  }
  const bits = calcEntropyBits(Number(lengthEl.value), charset.length);
  const pct = Math.max(0, Math.min(100, (bits / 160) * 100)); // scale bar up to 160 bits
  entropyBitsEl.textContent = `${bits.toFixed(1)} bits`;
  charsetSizeEl.textContent = `(charset size: ${charset.length})`;
  entropyMeterEl.style.width = `${pct}%`;

  // guidance
  if (bits >= 160) {
    entropyNoteEl.textContent = 'Excellent (≥160 bits). Suitable for very high-value secrets.';
  } else if (bits >= 128) {
    entropyNoteEl.textContent = 'Strong (≥128 bits). Good for master secrets.';
  } else if (bits >= 80) {
    entropyNoteEl.textContent = 'Moderate (≥80 bits). Consider increasing length/sets.';
  } else {
    entropyNoteEl.textContent = 'Low entropy. Increase length or add character sets.';
  }
}

function buildCharset() {
  let charset = '';
  if (uppercaseEl.checked) charset += CHARSETS.uppercase;
  if (lowercaseEl.checked) charset += CHARSETS.lowercase;
  if (digitsEl.checked) charset += CHARSETS.digits;
  if (symbolsEl.checked) charset += CHARSETS.symbols;
  return charset;
}

function selectedSets() {
  const sets = [];
  if (uppercaseEl.checked) sets.push(CHARSETS.uppercase);
  if (lowercaseEl.checked) sets.push(CHARSETS.lowercase);
  if (digitsEl.checked) sets.push(CHARSETS.digits);
  if (symbolsEl.checked) sets.push(CHARSETS.symbols);
  return sets;
}

function validate(silent = false) {
  const len = Number(lengthEl.value);
  const count = Number(countEl.value);
  const charset = buildCharset();
  let msg = '';

  if (!window.crypto || !window.crypto.getRandomValues) {
    msg = 'This browser lacks a cryptographically secure RNG (crypto.getRandomValues).';
  } else if (!charset.length) {
    msg = 'Select at least one character set.';
  } else if (len < LIMITS.minLen || len > LIMITS.maxLen) {
    msg = `Length must be between ${LIMITS.minLen} and ${LIMITS.maxLen}.`;
  } else if (count < LIMITS.minCount || count > LIMITS.maxCount) {
    msg = `Count must be between ${LIMITS.minCount} and ${LIMITS.maxCount}.`;
  } else if (len * count > LIMITS.maxTotalChars) {
    msg = 'Total character output is too large—reduce length or count.';
  } else if (enforceClassesEl.checked && len < selectedSets().length) {
    msg = 'Length must be ≥ the number of selected sets when enforcement is on.';
  }

  const valid = msg === '';
  if (!silent) {
    if (valid) {
      validationEl.classList.add('hidden');
      validationEl.textContent = '';
    } else {
      validationEl.classList.remove('hidden');
      validationEl.textContent = msg;
    }
  }
  return { valid, charset, message: msg };
}

// ======= CSPRNG helpers (unbiased) =======
const U32_MAX_PLUS_1 = 0x100000000; // 2^32

// Return a random integer in [0, n) without modulo bias
function randomIntBelow(n) {
  if (!(n > 0)) throw new Error('n must be > 0');
  const max = Math.floor(U32_MAX_PLUS_1 / n) * n; // largest multiple of n < 2^32
  const buf = new Uint32Array(64);
  for (;;) {
    crypto.getRandomValues(buf);
    for (let i = 0; i < buf.length; i++) {
      const x = buf[i];
      if (x < max) return x % n;
    }
  }
}

// Fisher–Yates shuffle using unbiased RNG
function shuffleArray(arr) {
  for (let i = arr.length - 1; i > 0; i--) {
    const j = randomIntBelow(i + 1);
    const t = arr[i]; arr[i] = arr[j]; arr[j] = t;
  }
  return arr;
}

function randomCharFromSet(set) {
  return set[randomIntBelow(set.length)];
}

// Generate one password
function generatePassword(len, charset, enforce) {
  const sets = selectedSets();
  const chars = [];

  if (enforce && sets.length > 0) {
    // ensure at least one from each selected set
    for (const s of sets) chars.push(randomCharFromSet(s));
  }
  // fill the rest from the full charset
  while (chars.length < len) {
    chars.push(charset[randomIntBelow(charset.length)]);
  }
  // shuffle to avoid predictable positions of enforced chars
  shuffleArray(chars);
  return chars.join('');
}

// ======= Clipboard & download =======
async function copyToClipboard(text) {
  if (!navigator.clipboard) { showToast('Clipboard not available in this environment.'); return false; }
  try {
    await navigator.clipboard.writeText(text);
    showToast('Copied to clipboard.');
    return true;
  } catch {
    showToast('Copy failed (permissions?).');
    return false;
  }
}

function downloadTxt(filename, content) {
  try {
    const blob = new Blob([content], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  } catch {
    showToast('Download failed.');
  }
}

// ======= UI wiring =======
const saved = new Set();

function renderSavedControls() {
  const count = saved.size;
  savedCountEl.textContent = `${count} saved`;
  if (count > 0) {
    savedControls.classList.remove('hidden');
    downloadAllBtn.disabled = false;
  } else {
    downloadAllBtn.disabled = true;
  }
}

function makeItem(password) {
  const wrapper = document.createElement('div');
  wrapper.className = 'item';

  const left = document.createElement('div');
  const secret = document.createElement('div');
  secret.className = 'secret';
  secret.textContent = password;
  left.appendChild(secret);

  // optional metadata line (length, entropy)
  const small = document.createElement('div');
  small.className = 'small';
  small.textContent = `len=${password.length}`;
  left.appendChild(small);

  const right = document.createElement('div');
  right.className = 'row';

  const copyBtn = document.createElement('button');
  copyBtn.className = 'icon-btn';
  copyBtn.title = 'Copy';
  copyBtn.textContent = 'Copy';
  copyBtn.addEventListener('click', () => { copyToClipboard(password); });

  const starBtn = document.createElement('button');
  starBtn.className = 'icon-btn';
  starBtn.title = 'Save (download TXT)';
  starBtn.textContent = 'Save';
  starBtn.addEventListener('click', () => {
    if (saved.has(password)) {
      saved.delete(password);
      starBtn.classList.remove('starred');
      starBtn.textContent = 'Save';
      showToast('Removed from saved.');
    } else {
      saved.add(password);
      starBtn.classList.add('starred');
      starBtn.textContent = 'Saved';
      const ts = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
      const content = `Generated Password\n==================\n\nPassword: ${password}\nGenerated: ${new Date().toString()}\nLength: ${password.length}\n\nSecurity note: generated locally with CSPRNG and unbiased selection.`;
      downloadTxt(`password_${ts}.txt`, content);
      showToast('Saved & downloaded.');
    }
    renderSavedControls();
  });

  right.appendChild(copyBtn);
  right.appendChild(starBtn);

  wrapper.appendChild(left);
  wrapper.appendChild(right);
  return wrapper;
}

function displayPasswords(passwords) {
  listEl.innerHTML = '';
  for (const p of passwords) listEl.appendChild(makeItem(p));
  resultsCard.classList.remove('hidden');
}

function generateMany() {
  const { valid, charset } = validate(false);
  if (!valid) return;

  const len = Number(lengthEl.value);
  const count = Number(countEl.value);
  const enforce = !!enforceClassesEl.checked;

  const out = [];
  for (let i = 0; i < count; i++) {
    out.push(generatePassword(len, charset, enforce));
  }
  displayPasswords(out);
  showToast(`Generated ${count} password${count > 1 ? 's' : ''}.`);
}

function downloadSavedTxt() {
  if (saved.size === 0) return;
  const arr = Array.from(saved);
  let content = `Saved Passwords\n===============\nGenerated: ${new Date().toString()}\nTotal: ${arr.length}\n\n`;
  for (let i = 0; i < arr.length; i++) content += `${i + 1}. ${arr[i]}\n`;
  content += `\nSecurity note: generated locally with CSPRNG and unbiased selection.`;
  const ts = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
  downloadTxt(`saved_passwords_${ts}.txt`, content);
  showToast('Saved passwords exported.');
}

function clearSaved() {
  saved.clear();
  renderSavedControls();
  // Also visually reset "Saved" buttons
  document.querySelectorAll('.item .icon-btn.starred').forEach(btn => {
    btn.classList.remove('starred'); btn.textContent = 'Save';
  });
  showToast('Saved list cleared (memory only).');
}

// ======= INIT =======
function wireEvents() {
  for (const id of ['length','count','uppercase','lowercase','digits','symbols','enforce-classes']) {
    el(id).addEventListener('input', () => { validate(false); updateEntropy(); });
    el(id).addEventListener('change', () => { validate(false); updateEntropy(); });
  }
  generateBtn.addEventListener('click', generateMany);
  downloadAllBtn.addEventListener('click', downloadSavedTxt);
  clearSavedBtn.addEventListener('click', clearSaved);

  // best-effort memory cleanup
  window.addEventListener('beforeunload', () => { saved.clear(); });
}

(function main() {
  const v = validate(false);
  updateEntropy();
  renderSavedControls();
  wireEvents();
})();