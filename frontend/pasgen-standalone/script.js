// ================================================
// Password Generator — script.js
// Pure vanilla JS. No dependencies.
// ================================================

// ------------------------------------------------
// Helpers
// ------------------------------------------------

/** Inclusive random integer in [min, max] */
function randomInt(min, max) {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}

/** Pick a random element from an array */
function randomPick(arr) {
  return arr[randomInt(0, arr.length - 1)];
}

/** Fisher-Yates shuffle (mutates and returns the array) */
function fisherYates(arr) {
  for (let i = arr.length - 1; i > 0; i--) {
    const j = randomInt(0, i);
    [arr[i], arr[j]] = [arr[j], arr[i]];
  }
  return arr;
}

// ------------------------------------------------
// Word lists for Memorable mode
// ------------------------------------------------
const ADJECTIVES = [
  'brave', 'calm', 'dark', 'easy', 'fast', 'glad', 'keen', 'loud',
  'mild', 'neat', 'pale', 'rich', 'soft', 'tall', 'warm', 'wild',
  'bold', 'cool', 'deep', 'fair', 'gold', 'high', 'kind', 'long',
  'noble', 'open', 'pure', 'rare', 'safe', 'true', 'vast', 'wise',
  'blue', 'gray', 'pink', 'red', 'amber', 'frost', 'jade', 'ruby'
];

const NOUNS = [
  'moon', 'star', 'tree', 'lake', 'wind', 'fire', 'rain', 'snow',
  'bird', 'dawn', 'dusk', 'peak', 'reef', 'sage', 'vine', 'wave',
  'cloud', 'creek', 'field', 'grove', 'hill', 'marsh', 'ridge', 'brook',
  'stone', 'river', 'tiger', 'wolf', 'eagle', 'maple', 'cedar', 'oak',
  'bear', 'deer', 'fox', 'hawk', 'lion', 'seal', 'coral', 'amber'
];

const SYMBOL_SEPARATORS = ['!', '@', '#', '%', '-', '_'];

// ------------------------------------------------
// Character pools
// ------------------------------------------------
const LETTERS  = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
const DIGITS   = '0123456789';
const SYMBOLS  = '!@#$%^&*()_+-=[]{}|;:,.<>?';

// ------------------------------------------------
// Generation functions (pure — no side effects)
// ------------------------------------------------

/**
 * Random password: letters + optional digits + optional symbols.
 * Guarantees at least one character from each enabled pool.
 */
function generateRandom(length, useNumbers, useSymbols) {
  let pool = LETTERS;
  if (useNumbers) pool += DIGITS;
  if (useSymbols) pool += SYMBOLS;

  const chars = [];

  // Force at least one from each enabled pool
  if (useNumbers) chars.push(randomPick(DIGITS));
  if (useSymbols) chars.push(randomPick(SYMBOLS));

  // Fill the rest
  const remaining = length - chars.length;
  for (let i = 0; i < remaining; i++) {
    chars.push(pool[randomInt(0, pool.length - 1)]);
  }

  // Shuffle so forced chars don't always appear at the start
  return fisherYates(chars).join('');
}

/**
 * Memorable password: word combinations with optional number suffix.
 * Length is approximate — words are picked greedily to stay near targetLength.
 */
function generateMemorable(targetLength, useNumbers, useSymbols) {
  const sep = useSymbols ? randomPick(SYMBOL_SEPARATORS) : '-';

  const words = [];
  let currentLen = 0;
  let useAdj = true; // alternate adj → noun → adj → noun …
  let iterations = 0;

  while (currentLen < targetLength && iterations < 30) {
    iterations++;
    const source = useAdj ? ADJECTIVES : NOUNS;
    const word = randomPick(source);
    useAdj = !useAdj;

    // First word: no separator prefix
    const addition = words.length === 0 ? word : sep + word;

    // Stop if adding this word would overshoot by more than 3 chars
    if (currentLen + addition.length > targetLength + 3) break;

    words.push(word);
    currentLen += addition.length;
  }

  let result = words.join(sep);

  // Optional numeric suffix
  if (useNumbers) {
    const num = String(randomInt(1, 99));
    result += num;
  }

  return result;
}

/**
 * PIN: pure digits, length 4–8.
 */
function generatePIN(length) {
  let pin = '';
  for (let i = 0; i < length; i++) {
    pin += String(randomInt(0, 9));
  }
  return pin;
}

// ------------------------------------------------
// State & DOM references
// ------------------------------------------------

const state = {
  type: 'random',   // 'random' | 'memorable' | 'pin'
  length: 20,
  numbers: true,
  symbols: false
};

const els = {
  segBtns:       document.querySelectorAll('.seg-btn'),
  slider:        document.getElementById('length-slider'),
  badge:         document.getElementById('length-badge'),
  numbersToggle: document.getElementById('numbers-toggle'),
  symbolsToggle: document.getElementById('symbols-toggle'),
  togglesWrap:   document.getElementById('toggles-container'),
  passwordEl:    document.getElementById('password-display'),
  copyBtn:       document.getElementById('copy-btn'),
  refreshBtn:    document.getElementById('refresh-btn')
};

// ------------------------------------------------
// UI sync — reads state, pushes to DOM
// ------------------------------------------------

function syncUI() {
  // 1. Segmented buttons
  els.segBtns.forEach(btn => {
    const active = btn.dataset.type === state.type;
    btn.classList.toggle('seg-btn--active', active);
    btn.setAttribute('aria-checked', String(active));
  });

  // 2. Slider min/max clamping for PIN mode
  if (state.type === 'pin') {
    els.slider.min  = '4';
    els.slider.max  = '8';
    state.length    = Math.min(Math.max(state.length, 4), 8);
  } else {
    els.slider.min  = '6';
    els.slider.max  = '32';
  }
  els.slider.value = String(state.length);

  // 3. Badge
  els.badge.textContent = String(state.length);

  // 4. Slider blue-fill via CSS custom property
  const min = Number(els.slider.min);
  const max = Number(els.slider.max);
  const pct = ((state.length - min) / (max - min)) * 100;
  els.slider.style.setProperty('--slider-pct', pct + '%');

  // 5. Toggles visibility
  els.togglesWrap.classList.toggle('toggles-container--hidden', state.type === 'pin');

  // 6. Toggle checked states
  els.numbersToggle.checked = state.numbers;
  els.symbolsToggle.checked = state.symbols;
}

// ------------------------------------------------
// Password rendering — per-character color spans
// ------------------------------------------------

function renderPassword(pw) {
  els.passwordEl.innerHTML = '';

  for (const ch of pw) {
    const span = document.createElement('span');
    span.textContent = ch;

    if (/[0-9]/.test(ch)) {
      span.classList.add('ch-number');     // blue
    } else if (/[^a-zA-Z]/.test(ch)) {
      span.classList.add('ch-symbol');     // mid-gray
    }
    // plain letters: no class, inherit dark color

    els.passwordEl.appendChild(span);
  }
}

// ------------------------------------------------
// Generation dispatcher
// ------------------------------------------------

function regenerate() {
  let pw;

  switch (state.type) {
    case 'random':
      pw = generateRandom(state.length, state.numbers, state.symbols);
      break;
    case 'memorable':
      pw = generateMemorable(state.length, state.numbers, state.symbols);
      break;
    case 'pin':
      pw = generatePIN(state.length);
      break;
  }

  renderPassword(pw);
}

// ------------------------------------------------
// Event wiring
// ------------------------------------------------

// Segmented control buttons
els.segBtns.forEach(btn => {
  btn.addEventListener('click', () => {
    state.type = btn.dataset.type;
    syncUI();
    regenerate();
  });
});

// Characters slider
els.slider.addEventListener('input', () => {
  state.length = Number(els.slider.value);
  syncUI();
  regenerate();
});

// Toggle switches
els.numbersToggle.addEventListener('change', () => {
  state.numbers = els.numbersToggle.checked;
  regenerate();
});

els.symbolsToggle.addEventListener('change', () => {
  state.symbols = els.symbolsToggle.checked;
  regenerate();
});

// Refresh button
els.refreshBtn.addEventListener('click', regenerate);

// Copy button
els.copyBtn.addEventListener('click', async () => {
  const pw = els.passwordEl.textContent;

  try {
    await navigator.clipboard.writeText(pw);
  } catch {
    // Fallback for non-secure contexts (e.g. file:// protocol)
    const ta = document.createElement('textarea');
    ta.value = pw;
    ta.style.position = 'fixed';
    ta.style.opacity = '0';
    ta.style.left = '-9999px';
    document.body.appendChild(ta);
    ta.select();
    document.execCommand('copy');
    document.body.removeChild(ta);
  }

  // Brief "Copied!" feedback
  const original = els.copyBtn.textContent;
  els.copyBtn.textContent = 'Copied!';
  setTimeout(() => { els.copyBtn.textContent = original; }, 1500);
});

// ------------------------------------------------
// Init
// ------------------------------------------------
syncUI();
regenerate();
