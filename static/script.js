// ══════════════════════════════════════════════
//  NAVIGATION
// ══════════════════════════════════════════════
const pages = ['footprint', 'password', 'phishing', 'wifi', 'dashboard'];
const labels = {
  footprint: 'Digital Footprint',
  password:  'Password Analyser',
  phishing:  'Phishing Detector',
  wifi:      'Wi-Fi Risk Indicator',
  dashboard: 'Dashboard'
};

let currentPage = 'footprint';

function navigate(page) {
  pages.forEach(p => {
    document.getElementById('page-' + p).classList.remove('active');
    document.getElementById('nav-' + p).classList.remove('active');
  });
  document.getElementById('page-' + page).classList.add('active');
  document.getElementById('nav-' + page).classList.add('active');
  document.getElementById('bc-current').textContent = labels[page];
  currentPage = page;
  if (window.innerWidth < 900) closeSidebar();
  document.querySelector('.main-content').scrollTop = 0;
  window.scrollTo(0, 0);
}

// ══════════════════════════════════════════════
//  SIDEBAR TOGGLE
// ══════════════════════════════════════════════
let sidebarOpen = false;

function toggleSidebar() {
  sidebarOpen ? closeSidebar() : openSidebar();
}

function openSidebar() {
  document.getElementById('sidebar').classList.add('open');
  document.getElementById('overlay').classList.add('active');
  document.getElementById('hamburger').classList.add('open');
  sidebarOpen = true;
}

function closeSidebar() {
  document.getElementById('sidebar').classList.remove('open');
  document.getElementById('overlay').classList.remove('active');
  document.getElementById('hamburger').classList.remove('open');
  sidebarOpen = false;
}

// ══════════════════════════════════════════════
//  HELPERS
// ══════════════════════════════════════════════
let wifiIsPublic = true;

function setWifiPublic(val) {
  wifiIsPublic = val;
  document.getElementById('wf-public-btn').classList.toggle('selected', val);
  document.getElementById('wf-private-btn').classList.toggle('selected', !val);
}

function statusClass(s) {
  const m = {
    SAFE: 's-safe', STRONG: 's-strong', LOW: 's-low',
    MEDIUM: 's-medium', HIGH: 's-high', WEAK: 's-weak', ERROR: 's-error'
  };
  return m[s] || 's-error';
}

function setSpinner(id, on) {
  document.getElementById(id).style.display = on ? 'block' : 'none';
}

function makeList(el, items) {
  el.innerHTML = '';
  (items || []).forEach(i => {
    const li = document.createElement('li');
    li.textContent = i;
    el.appendChild(li);
  });
}

function sleep(ms) {
  return new Promise(r => setTimeout(r, ms));
}

// ══════════════════════════════════════════════
//  MODULE 1: DIGITAL FOOTPRINT
// ══════════════════════════════════════════════
const BREACH_KEYWORDS = [
  "pastebin", "leak", "dump", "breach", "hacked", "exposed", "darkweb",
  "dark web", "data breach", "credential", "pwned", "compromised",
  "stolen", "harvested", "exfiltrated"
];

function checkFootprint(text) {
  if (!text || !text.trim()) {
    return { status: 'ERROR', matched_keywords: [], message: 'No text provided for analysis.' };
  }
  const norm = text.toLowerCase();
  const matched = BREACH_KEYWORDS.filter(kw => norm.includes(kw));
  if (matched.length) {
    return {
      status: 'HIGH',
      matched_keywords: matched,
      message: `⚠️ High risk! Your text contains ${matched.length} breach indicator(s): ${matched.join(', ')}. This content may be associated with a data leak or breach. Change affected passwords immediately and check haveibeenpwned.com.`
    };
  }
  return {
    status: 'SAFE',
    matched_keywords: [],
    message: '✅ No breach indicators detected in the provided text. Your digital footprint looks clean.'
  };
}

async function runFootprint() {
  const text = document.getElementById('fp-text').value;
  if (!text.trim()) { alert('Please paste some text to analyse.'); return; }
  setSpinner('fp-spinner', true);
  await sleep(400);
  try {
    const r = checkFootprint(text);
    const panel = document.getElementById('fp-result');
    const badge = document.getElementById('fp-status-badge');
    badge.textContent = r.status;
    badge.className = 'status-badge ' + statusClass(r.status);
    document.getElementById('fp-message').textContent = r.message;
    if (r.matched_keywords && r.matched_keywords.length) {
      document.getElementById('fp-keywords-section').style.display = 'block';
      makeList(document.getElementById('fp-keywords'), r.matched_keywords);
    } else {
      document.getElementById('fp-keywords-section').style.display = 'none';
    }
    panel.classList.add('visible');
  } finally {
    setSpinner('fp-spinner', false);
  }
}

// ══════════════════════════════════════════════
//  MODULE 2: PASSWORD ANALYSER
// ══════════════════════════════════════════════
const PW_RULES = [
  {
    id: 'length',
    desc: 'At least 8 characters long',
    test: p => p.length >= 8,
    tip: "Use at least 8 characters. Consider a passphrase like 'Coffee@Morning!2024'."
  },
  {
    id: 'uppercase',
    desc: 'Contains at least one uppercase letter (A–Z)',
    test: p => /[A-Z]/.test(p),
    tip: 'Add at least one UPPERCASE letter (e.g., A, B, C...).'
  },
  {
    id: 'lowercase',
    desc: 'Contains at least one lowercase letter (a–z)',
    test: p => /[a-z]/.test(p),
    tip: 'Add at least one lowercase letter (e.g., a, b, c...).'
  },
  {
    id: 'digit',
    desc: 'Contains at least one numeric digit (0–9)',
    test: p => /[0-9]/.test(p),
    tip: 'Include at least one number (0–9) in your password.'
  },
  {
    id: 'special',
    desc: 'Contains at least one special character (!@#...)',
    test: p => /[!@#$%^&*()\-_=+\[\]{};':"\\|,.<>\/?`~]/.test(p),
    tip: 'Add a special character like !, @, #, $, %, ^, &, or *.'
  }
];

function analysePassword(password) {
  if (!password) {
    return { status: 'ERROR', score: 0, max_score: 5, rules_passed: [], tips: [], message: 'No password provided.' };
  }
  let score = 0;
  const tips = [];
  const rules_passed = [];
  for (const rule of PW_RULES) {
    if (rule.test(password)) { score++; rules_passed.push(rule.desc); }
    else { tips.push(rule.tip); }
  }
  let status, message;
  if (score <= 2) {
    status = 'WEAK';
    message = '❌ Weak password. This password can be cracked almost instantly. Apply the improvement tips below.';
  } else if (score <= 4) {
    status = 'MEDIUM';
    message = '⚠️ Medium-strength password. Good start, but it can still be improved. Follow the remaining tips.';
  } else {
    status = 'STRONG';
    message = '✅ Strong password! Your password meets all 5 security criteria. Great job staying secure.';
  }
  return { status, score, max_score: 5, rules_passed, tips, message };
}

function updateMeter(val) {
  if (!val) { document.getElementById('pw-meter').style.display = 'none'; return; }
  document.getElementById('pw-meter').style.display = 'block';
  const score = PW_RULES.filter(r => r.test(val)).length;
  const colors = ['var(--red)', 'var(--red)', 'var(--orange)', 'var(--yellow)', 'var(--green)', 'var(--green)'];
  for (let i = 1; i <= 5; i++) {
    document.getElementById('pwb' + i).style.background = i <= score ? colors[score] : 'var(--border)';
  }
  document.getElementById('pw-score-text').textContent = score + ' / 5 rules passed';
}

async function runPassword() {
  const pw = document.getElementById('pw-input').value;
  if (!pw) { alert('Please enter a password.'); return; }
  setSpinner('pw-spinner', true);
  await sleep(350);
  try {
    const r = analysePassword(pw);
    const badge = document.getElementById('pw-status-badge');
    badge.textContent = r.status;
    badge.className = 'status-badge ' + statusClass(r.status);
    document.getElementById('pw-score-display').textContent = `Score: ${r.score}/${r.max_score}`;
    document.getElementById('pw-message').textContent = r.message;
    if (r.tips && r.tips.length) {
      document.getElementById('pw-tips-section').style.display = 'block';
      makeList(document.getElementById('pw-tips'), r.tips);
    } else { document.getElementById('pw-tips-section').style.display = 'none'; }
    if (r.rules_passed && r.rules_passed.length) {
      document.getElementById('pw-rules-section').style.display = 'block';
      makeList(document.getElementById('pw-rules'), r.rules_passed);
    } else { document.getElementById('pw-rules-section').style.display = 'none'; }
    document.getElementById('pw-result').classList.add('visible');
  } finally {
    setSpinner('pw-spinner', false);
  }
}

// ══════════════════════════════════════════════
//  MODULE 3: PHISHING DETECTOR
// ══════════════════════════════════════════════
const KNOWN_LEGIT = [
  "google.com", "paypal.com", "amazon.com", "facebook.com", "microsoft.com",
  "apple.com", "netflix.com", "instagram.com", "twitter.com", "linkedin.com",
  "sbi.co.in", "hdfcbank.com", "icicibank.com", "flipkart.com", "paytm.com"
];
const SUSP_KW = [
  "login", "verify", "urgent", "confirm", "update", "secure", "account",
  "bank", "password", "credentials", "suspended", "blocked", "alert",
  "warning", "limited", "validate", "signin"
];
const HIGH_RISK_TLDS = [
  ".xyz", ".tk", ".ml", ".cf", ".gq", ".pw", ".top",
  ".click", ".download", ".link", ".online", ".site"
];

function levenshtein(s1, s2) {
  if (s1.length < s2.length) return levenshtein(s2, s1);
  if (s2.length === 0) return s1.length;
  let prev = Array.from({ length: s2.length + 1 }, (_, i) => i);
  for (let i = 0; i < s1.length; i++) {
    const cur = [i + 1];
    for (let j = 0; j < s2.length; j++) {
      cur.push(Math.min(prev[j + 1] + 1, cur[j] + 1, prev[j] + (s1[i] !== s2[j] ? 1 : 0)));
    }
    prev = cur;
  }
  return prev[s2.length];
}

function analysePhishing(rawUrl) {
  if (!rawUrl || !rawUrl.trim()) {
    return { status: 'ERROR', score: 0, flags: [], message: 'No URL provided.' };
  }
  let url = rawUrl.trim();
  if (!url.startsWith('http://') && !url.startsWith('https://')) url = 'http://' + url;

  const flags = [];
  let score = 0;

  try {
    const parsed = new URL(url);
    const hostname = parsed.hostname || '';
    const full = url.toLowerCase();

    // Signal 1: No HTTPS
    if (parsed.protocol === 'http:') {
      flags.push('No HTTPS — connection is not encrypted (plaintext risk)');
      score += 2;
    }

    // Signal 2: Suspicious keywords
    const kwFound = SUSP_KW.filter(kw => full.includes(kw));
    if (kwFound.length) {
      flags.push(`Suspicious keywords detected: ${kwFound.join(', ')}`);
      score += kwFound.length;
    }

    // Signal 3: High-risk TLD
    const riskyTld = HIGH_RISK_TLDS.find(tld => hostname.endsWith(tld));
    if (riskyTld) {
      flags.push(`High-risk TLD detected: ${riskyTld}`);
      score += 2;
    }

    // Signal 4: IP-based URL
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(hostname)) {
      flags.push('IP-based URL — legitimate sites use domain names, not raw IPs');
      score += 3;
    }

    // Signal 5: Excessive subdomains
    const parts = hostname.split('.');
    if (parts.length > 3) {
      flags.push(`Excessive subdomain depth (${parts.length} levels) — common obfuscation trick`);
      score += 1;
    }

    // Signal 6: Lookalike domain (Levenshtein)
    const baseDomain = parts.length >= 2 ? parts.slice(-2).join('.') : hostname;
    for (const legit of KNOWN_LEGIT) {
      const dist = levenshtein(baseDomain.toLowerCase(), legit.toLowerCase());
      if (dist > 0 && dist <= 2) {
        flags.push(`Lookalike domain! '${baseDomain}' is suspiciously similar to '${legit}' (edit distance: ${dist})`);
        score += 3;
        break;
      }
    }

    // Signal 7: @ in URL
    if (url.includes('@')) {
      flags.push("'@' symbol in URL — used to redirect to a different host (redirection trick)");
      score += 2;
    }

    // Signal 8: Punycode
    if (hostname.includes('xn--')) {
      flags.push('Punycode domain (xn--) detected — internationalized character spoofing attempt');
      score += 2;
    }

    // Signal 9: Long URL
    if (url.length > 100) {
      flags.push(`URL is very long (${url.length} chars) — often used to hide the real destination`);
      score += 1;
    }

  } catch (e) {
    return { status: 'ERROR', score: 0, flags: [`Could not parse URL: ${e.message}`], message: 'Invalid URL format.' };
  }

  let status, message;
  if (score <= 1) {
    status = 'SAFE';
    message = '✅ URL appears safe. No significant phishing signals detected.';
  } else if (score <= 3) {
    status = 'MEDIUM';
    message = `⚠️ Suspicious URL. ${flags.length} risk signal(s) detected. Proceed with caution.`;
  } else {
    status = 'HIGH';
    message = `🚨 High phishing risk! ${flags.length} danger signal(s) detected. Do NOT visit this URL.`;
  }
  return { status, score, flags, message };
}

async function runPhishing() {
  const url = document.getElementById('ph-url').value;
  if (!url.trim()) { alert('Please enter a URL.'); return; }
  setSpinner('ph-spinner', true);
  await sleep(400);
  try {
    const r = analysePhishing(url);
    const badge = document.getElementById('ph-status-badge');
    badge.textContent = r.status;
    badge.className = 'status-badge ' + statusClass(r.status);
    document.getElementById('ph-score-display').textContent = `Risk Score: ${r.score}`;
    document.getElementById('ph-message').textContent = r.message;
    if (r.flags && r.flags.length) {
      document.getElementById('ph-flags-section').style.display = 'block';
      makeList(document.getElementById('ph-flags'), r.flags);
    } else { document.getElementById('ph-flags-section').style.display = 'none'; }
    document.getElementById('ph-result').classList.add('visible');
  } finally {
    setSpinner('ph-spinner', false);
  }
}

// ══════════════════════════════════════════════
//  MODULE 4: WI-FI RISK
// ══════════════════════════════════════════════
const ENC_SCORES = { OPEN: 3, WEP: 2, WPA: 1, WPA2: 1, WPA3: 0 };
const ENC_INFO = {
  OPEN:  'No encryption — all traffic is visible to anyone on the same network.',
  WEP:   'WEP is broken and can be cracked in under 60 seconds with free tools.',
  WPA:   'WPA has known vulnerabilities and is considered outdated.',
  WPA2:  'WPA2 is standard but vulnerable to KRACK attacks on public networks.',
  WPA3:  'WPA3 is the most secure modern Wi-Fi standard. Good choice.'
};

function assessWifi(encryption, is_public, ssid = '') {
  encryption = (encryption || 'OPEN').toUpperCase().trim();
  if (!(encryption in ENC_SCORES)) {
    return { status: 'ERROR', score: 0, encryption, flags: [], tips: [], message: `Unknown encryption type: '${encryption}'.` };
  }

  let score = ENC_SCORES[encryption];
  const flags = [], tips = [];

  if (is_public) {
    score += 1;
    flags.push('Public network — shared with unknown users and potentially monitored');
  }
  if (is_public && (encryption === 'OPEN' || encryption === 'WPA2')) {
    flags.push('Evil twin hotspot risk — an attacker may create a fake access point with the same name');
    tips.push('Verify the exact network name (SSID) with staff before connecting');
  }
  if (is_public && encryption === 'OPEN') {
    flags.push('Captive portal likely — your device will auto-connect and expose your MAC address');
  }
  if (encryption === 'OPEN') {
    flags.push('MITM (Man-in-the-Middle) attack risk — attacker can intercept all unencrypted traffic');
    tips.push('Never use this network for banking, email, or any sensitive login');
    tips.push('Use your mobile data hotspot instead of this open network');
  }
  if (encryption === 'WEP' || encryption === 'WPA') {
    flags.push(`Outdated encryption (${encryption}) — upgrade to WPA2 or WPA3 if possible`);
  }
  if (is_public) {
    tips.push('Always use a trusted VPN when connecting to any public Wi-Fi network');
    tips.push('Avoid accessing banking, email, or work accounts on public Wi-Fi');
    tips.push("Enable 'Forget Network' after use to prevent auto-reconnect");
  }
  if (encryption === 'WPA3') {
    tips.push('WPA3 is the safest option. Your encryption is up to date.');
  }

  let status, message;
  if (score === 0) {
    status = 'SAFE';
    message = '✅ Low risk. WPA3 private network — excellent security posture.';
  } else if (score <= 2) {
    status = 'MEDIUM';
    message = `⚠️ Moderate risk. ${flags.length} concern(s) detected. Take precautions before transmitting sensitive data.`;
  } else {
    status = 'HIGH';
    message = `🚨 High risk! ${flags.length} serious risk(s) detected. Avoid sensitive activities on this network.`;
  }

  return { status, score, encryption, encryption_info: ENC_INFO[encryption] || '', flags, tips, message };
}

async function runWifi() {
  const enc = document.getElementById('wf-enc').value;
  const ssid = document.getElementById('wf-ssid').value;
  setSpinner('wf-spinner', true);
  await sleep(350);
  try {
    const r = assessWifi(enc, wifiIsPublic, ssid);
    const badge = document.getElementById('wf-status-badge');
    badge.textContent = r.status;
    badge.className = 'status-badge ' + statusClass(r.status);
    document.getElementById('wf-enc-display').textContent = `Encryption: ${r.encryption}`;
    document.getElementById('wf-message').textContent = r.message;
    if (r.flags && r.flags.length) {
      document.getElementById('wf-flags-section').style.display = 'block';
      makeList(document.getElementById('wf-flags'), r.flags);
    } else { document.getElementById('wf-flags-section').style.display = 'none'; }
    if (r.tips && r.tips.length) {
      document.getElementById('wf-tips-section').style.display = 'block';
      makeList(document.getElementById('wf-tips'), r.tips);
    } else { document.getElementById('wf-tips-section').style.display = 'none'; }
    document.getElementById('wf-result').classList.add('visible');
  } finally {
    setSpinner('wf-spinner', false);
  }
}

// ══════════════════════════════════════════════
//  DASHBOARD: FULL SCAN
// ══════════════════════════════════════════════
const STATUS_WEIGHT = { HIGH: 2, WEAK: 2, MEDIUM: 1, LOW: 0, SAFE: 0, STRONG: 0, ERROR: 0 };

function buildDashboard(fpR, pwR, phR, wfR) {
  const results = { footprint: fpR, password: pwR, phishing: phR, wifi: wfR };
  let total = 0;
  const breakdown = {};
  for (const [mod, res] of Object.entries(results)) {
    const status = res.status || 'ERROR';
    const weight = STATUS_WEIGHT[status] || 0;
    total += weight;
    breakdown[mod] = { status, weight, message: res.message || '' };
  }
  const MAX = 8;
  const pct = (total / MAX) * 100;
  let overall_status, summary;
  if (total === 0) {
    overall_status = 'SAFE';
    summary = '🛡️ Excellent! Your digital security posture is strong across all four dimensions. Keep it up!';
  } else if (pct <= 40) {
    overall_status = 'LOW';
    summary = '✅ Low overall risk. A few minor issues were detected. Review the flagged modules and apply the suggested improvements.';
  } else if (pct <= 70) {
    overall_status = 'MEDIUM';
    summary = "⚠️ Moderate risk detected across your security profile. Several areas need attention — please review each module's recommendations.";
  } else {
    overall_status = 'HIGH';
    summary = '🚨 High overall cyber risk! Multiple serious vulnerabilities detected. Take immediate action on all flagged modules.';
  }
  return { overall_status, summary, score: total, max_score: MAX, percentage: Math.round(pct * 10) / 10, breakdown };
}

async function runScanAll() {
  const btn = document.getElementById('scan-all-btn');
  setSpinner('scan-all-spinner', true);
  btn.disabled = true;
  document.getElementById('dash-result-wrap').style.display = 'none';
  document.getElementById('dash-placeholder').style.display = 'none';
  await sleep(600);
  try {
    const text = document.getElementById('sa-text').value;
    const pw   = document.getElementById('sa-password').value;
    const url  = document.getElementById('sa-url').value;
    const enc  = document.getElementById('sa-encryption').value;
    const pub  = document.getElementById('sa-public').value === 'true';

    const fpR = checkFootprint(text);
    const pwR = analysePassword(pw);
    const phR = analysePhishing(url);
    const wfR = assessWifi(enc, pub);

    const d = buildDashboard(fpR, pwR, phR, wfR);

    const pct = d.percentage;
    const color = pct <= 40 ? 'var(--green)' : pct <= 70 ? 'var(--yellow)' : 'var(--red)';

    const scoreEl = document.getElementById('dash-score');
    scoreEl.textContent = d.score + ' / ' + d.max_score;
    scoreEl.style.color = color;

    const labelEl = document.getElementById('dash-label');
    labelEl.textContent = d.overall_status;
    labelEl.style.color = color;

    document.getElementById('dash-summary').textContent = d.summary;

    const grid = document.getElementById('dash-breakdown');
    grid.innerHTML = '';
    const icons = { footprint: '🔍', password: '🔐', phishing: '🎣', wifi: '📡' };
    const names = { footprint: 'Footprint', password: 'Password', phishing: 'Phishing', wifi: 'Wi-Fi' };

    for (const [mod, info] of Object.entries(d.breakdown)) {
      const card = document.createElement('div');
      card.className = 'breakdown-card';
      const snippet = info.message.replace(/^[🛡️✅⚠️🚨❌]+\s*/, '').substring(0, 90);
      card.innerHTML = `
        <div class="mod-name">${icons[mod] || ''} ${names[mod] || mod}</div>
        <span class="status-badge ${statusClass(info.status)}">${info.status}</span>
        <div style="font-size:0.78rem;color:var(--text-dim);margin-top:8px;line-height:1.5">
          ${snippet}${info.message.length > 90 ? '…' : ''}
        </div>
      `;
      grid.appendChild(card);
    }

    document.getElementById('dash-result-wrap').style.display = 'block';
    document.getElementById('dash-result-wrap').scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  } finally {
    setSpinner('scan-all-spinner', false);
    btn.disabled = false;
  }
}
