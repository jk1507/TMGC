/**
 * script.js — Suspicious Domain Detection System Frontend
 * Handles: API calls, UI rendering, real-time monitoring, example domains
 */

"use strict";

// ──────────────────────────────────────────────────────────────────────────────
// CONFIGURATION
// ──────────────────────────────────────────────────────────────────────────────
const CONFIG = {
    apiBase: (function () {
        // Prefer local backend during development
        if (location.protocol === "file:" || location.hostname === "localhost" || location.hostname === "127.0.0.1") {
            return "http://localhost:5001";
        }
        return "https://tmgc.onrender.com";
    })(),
    analysisTimeout: 15000,   // 15s timeout
    monitorInterval: 30000,   // 30s for real-time monitor simulation
    maxMonitorHistory: 10,
};

// ──────────────────────────────────────────────────────────────────────────────
// STATE
// ──────────────────────────────────────────────────────────────────────────────
let monitorInterval = null;
let scanStartTime = null;
let currentResults = null;

// ──────────────────────────────────────────────────────────────────────────────
// INIT
// ──────────────────────────────────────────────────────────────────────────────
document.addEventListener("DOMContentLoaded", () => {
    checkBackendHealth();
    loadExamples();
    bindKeyboard();
    startMonitorSimulation();
});

// ──────────────────────────────────────────────────────────────────────────────
// HEALTH CHECK
// ──────────────────────────────────────────────────────────────────────────────
async function checkBackendHealth() {
    const dot = document.getElementById("statusDot");
    const text = document.getElementById("statusText");

    try {
        const res = await fetch(`${CONFIG.apiBase}/health`, { signal: AbortSignal.timeout(4000) });
        if (res.ok) {
            const data = await res.json();
            dot.classList.add("online");
            text.textContent = `ONLINE — ML: ${data.ml_model.toUpperCase()}`;
        } else {
            throw new Error("Non-OK response");
        }
    } catch {
        dot.classList.add("offline");
        text.textContent = "BACKEND OFFLINE";
        showError("Backend is not reachable. Make sure Flask is running on port 5000.");
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// KEYBOARD BINDING
// ──────────────────────────────────────────────────────────────────────────────
function bindKeyboard() {
    const input = document.getElementById("domainInput");
    input.addEventListener("keydown", (e) => {
        if (e.key === "Enter") analyzeDomain();
        hideError();
    });
}

// ──────────────────────────────────────────────────────────────────────────────
// LOAD EXAMPLES FROM BACKEND
// ──────────────────────────────────────────────────────────────────────────────
async function loadExamples() {
    try {
        const res = await fetch(`${CONFIG.apiBase}/examples`, { signal: AbortSignal.timeout(4000) });
        const data = await res.json();
        renderExamples(data.examples || []);
    } catch {
        // Use hardcoded fallback examples
        renderExamples([
            { domain: "paypa1.com", expected: "Homoglyph" },
            { domain: "gooogle.com", expected: "Typosquatting" },
            { domain: "paypal-login.com", expected: "Combo-Squatting" },
            { domain: "secure-netflix-verify.xyz", expected: "Multi-vector" },
            { domain: "g00gle.com", expected: "Digit Substitution" },
            { domain: "faceboook.com", expected: "Typosquatting" },
            { domain: "amazon.com", expected: "Legitimate" },
        ]);
    }
}

function renderExamples(examples) {
    const grid = document.getElementById("examplesGrid");
    grid.innerHTML = "";

    const riskLevels = {
        "Legitimate": "low",
        "Homoglyph": "high",
        "Typosquatting": "high",
        "Combo-Squatting": "high",
        "Multi-vector": "high",
        "Digit Substitution": "high",
    };

    examples.forEach((ex) => {
        const level = riskLevels[ex.expected] || "medium";
        const chip = document.createElement("button");
        chip.className = "example-chip";
        chip.innerHTML = `
      <span class="chip-dot chip-${level}"></span>
      <span>${ex.domain}</span>
    `;
        chip.title = `Expected: ${ex.expected}`;
        chip.addEventListener("click", () => {
            document.getElementById("domainInput").value = ex.domain;
            document.getElementById("domainInput").focus();
            analyzeDomain();
        });
        grid.appendChild(chip);
    });
}

// ──────────────────────────────────────────────────────────────────────────────
// MAIN ANALYSIS FLOW
// ──────────────────────────────────────────────────────────────────────────────
async function analyzeDomain() {
    const input = document.getElementById("domainInput");
    const domain = input.value.trim();
    const official = (document.getElementById("officialInput")?.value || "").trim();

    if (!domain) {
        showError("Please enter a domain name to analyze.");
        input.focus();
        return;
    }

    // Basic client-side validation
    if (!domain.includes(".")) {
        showError("Invalid domain — must contain at least one dot (e.g. example.com).");
        return;
    }

    hideError();
    hideResults();
    showLoader();

    scanStartTime = Date.now();

    // Animate loader steps
    const steps = [
        "Resolving domain structure...",
        "Running Levenshtein & Jaro-Winkler analysis...",
        "Checking homoglyph character map...",
        "Analyzing combo-squatting patterns...",
        "Querying WHOIS metadata...",
        "Running ML classifier...",
        "Computing risk score...",
    ];
    let stepIndex = 0;
    const stepsEl = document.getElementById("loaderSteps");
    const stepTimer = setInterval(() => {
        if (stepIndex < steps.length) {
            stepsEl.textContent = steps[stepIndex++];
        }
    }, 280);

    try {
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), CONFIG.analysisTimeout);

        const res = await fetch(`${CONFIG.apiBase}/analyze-domain`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ domain, inspect_website: true, official_domain: official || undefined }),
            signal: controller.signal,
        });

        clearTimeout(timeout);
        clearInterval(stepTimer);

        if (!res.ok) {
    const errData = await res.json();
    console.log("FULL ERROR:", errData);   // 🔥 NOW WILL PRINT
    showError(errData.detail || errData.error);
    return;
}   

        const data = await res.json();
        currentResults = data;

        hideLoader();
        renderResults(data);

        // Trigger alert for high-risk domains
        if (data.risk_level === "High" || data.risk_level === "Critical") {
            triggerAlert(data);
        }

    } catch (err) {
        clearInterval(stepTimer);
        hideLoader();

        if (err.name === "AbortError") {
            showError("Analysis timed out. Check that the backend is running.");
        } else {
            showError(err.message || "Analysis failed. Please try again.");
        }
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// RENDER RESULTS
// ──────────────────────────────────────────────────────────────────────────────
function renderResults(data) {
    const panel = document.getElementById("resultsPanel");
    panel.style.display = "block";

    // ── Header ──────────────────────────────────────────────────────────────
    document.getElementById("resultDomain").textContent = data.domain;

    const badge = document.getElementById("resultBadge");
    const finalLevel = data.risk_level;

    const verdict = (typeof data.is_fake === "boolean")
        ? (data.is_fake ? "FAKE / PHISHING LIKELY" : "LIKELY LEGIT")
        : `${finalLevel.toUpperCase()} RISK`;
    badge.textContent = verdict;
    badge.className = `result-badge badge-${finalLevel.toLowerCase()}`;

    // ── Metrics ─────────────────────────────────────────────────────────────
    const scoreVal = document.getElementById("scoreValue");
    const finalScore = Math.round((data.score ?? data.risk_score ?? 0) * 1);
    scoreVal.textContent = finalScore;
    scoreVal.className = `metric-value text-${finalLevel.toLowerCase()} glow-${riskToGlow(finalLevel)}`;

    // Animate score bar
    const bar = document.getElementById("scoreBar");
    bar.style.width = "0%";
    bar.style.background = riskToColor(finalLevel);
    setTimeout(() => { bar.style.width = `${finalScore}%`; }, 100);

    const lvlEl = document.getElementById("riskLevel");
    lvlEl.textContent = finalLevel;
    lvlEl.className = `metric-value text-${finalLevel.toLowerCase()} glow-${riskToGlow(finalLevel)}`;
    const attackEl = document.getElementById("attackType");
    attackEl.textContent = data.attack_type;
    attackEl.className = "metric-value metric-attack";

    document.getElementById("domainAge").textContent = data.domain_age || "Unknown";
    document.getElementById("domainAgeNote").textContent =
        `Registered: ${data.creation_date || "?"}`;

    // ── WHOIS Grid ───────────────────────────────────────────────────────────
    renderWhois(data);

    // ── Detection Signals ────────────────────────────────────────────────────
    renderDetection(data);

    // ── Website inspection ───────────────────────────────────────────────────
    renderWebsiteInspection(data.website || null);

    // ── Domain Features ──────────────────────────────────────────────────────
    renderFeatures(data.features || {});

    // ── Score Breakdown ──────────────────────────────────────────────────────
    renderBreakdown(data.score_breakdown || {});

    // ── ML ───────────────────────────────────────────────────────────────────
    renderML(data.ml_classification || {});
    renderPhishTank(data);
    function renderPhishTank(data) {
    const section = document.getElementById("mlSection");

    if (!data.phishtank || !data.phishtank.pt_available) return;

    const pt = data.phishtank;

    // Decide status
    let verdict = "UNKNOWN";
    let colorClass = "text-medium";

    if (pt.is_phishing && pt.verified) {
        verdict = "CONFIRMED PHISHING";
        colorClass = "text-high glow-red";
    } else if (pt.is_phishing) {
        verdict = "POSSIBLE PHISHING";
        colorClass = "text-medium glow-yellow";
    } else {
        verdict = "NOT FOUND";
        colorClass = "text-low glow-green";
    }

    const html = `
    <div class="detail-section">
        <div class="detail-title">
            <span class="detail-icon">◈</span> REAL WORLD THREAT (PHISHTANK)
        </div>

        <div class="ml-result">
            <div class="ml-verdict ${colorClass}">
                ${verdict}
            </div>

            <div class="ml-prob">
                In Database: <strong>${pt.is_phishing ? "YES" : "NO"}</strong>
                &nbsp;·&nbsp;
                Verified: <strong>${pt.verified ? "YES" : "NO"}</strong>
            </div>
        </div>
    </div>
    `;

    // Insert BELOW ML section (same flow)
    section.insertAdjacentHTML("afterend", html);
}

    // ── Scan time ────────────────────────────────────────────────────────────
    const elapsed = ((Date.now() - scanStartTime) / 1000).toFixed(2);
    document.getElementById("scanTime").textContent = `SCAN TIME: ${elapsed}s`;

    // Scroll to results
    panel.scrollIntoView({ behavior: "smooth", block: "start" });
    // 🚨 Trigger BIG alert if score >= 60 (high/critical)
    if ((data.score ?? data.risk_score ?? 0) >= 60) {
        triggerHighAlert(data);
    }
}

function renderWebsiteInspection(website) {
    const section = document.getElementById("websiteSection");
    const grid = document.getElementById("websiteGrid");
    if (!section || !grid) return;

    if (!website) {
        section.style.display = "none";
        return;
    }

    section.style.display = "block";

    if (!website.available) {
        const err = website.error || website.note || website.source || "Unavailable";
        grid.innerHTML = `
      <div class="detail-item">
        <div class="detail-item-label">STATUS</div>
        <div class="detail-item-value text-medium">${escHtml(String(err))}</div>
      </div>
    `;
        return;
    }

    const sig = website.signals || {};
    const redirects = (website.redirect_chain || []).map(r => `${r.code} ${r.from} → ${r.to}`).slice(0, 5);
    const extActions = (sig.external_form_actions || []).slice(0, 5);

    const items = [
        { label: "FINAL URL", value: website.final_url || website.start_url || "—" },
        { label: "HTTP STATUS", value: website.status ?? "—", flag: (website.status && website.status >= 400) },
        { label: "TITLE", value: sig.title || "—" },
        { label: "HAS FORM", value: sig.has_form ? "YES" : "NO", flag: sig.has_form },
        { label: "PASSWORD INPUT", value: sig.has_password_input ? "YES" : "NO", flag: sig.has_password_input },
        { label: "EMAIL INPUT", value: sig.has_email_input ? "YES" : "NO", flag: sig.has_email_input },
        { label: "OTP KEYWORDS", value: sig.has_otp_keywords ? "YES" : "NO", flag: sig.has_otp_keywords },
        { label: "REDIRECTS", value: redirects.length ? redirects.join(" | ") : "None" },
        { label: "EXTERNAL FORM ACTIONS", value: extActions.length ? extActions.join(" | ") : "None", flag: extActions.length > 0 },
    ];

    // add clone check if present in API response
    const clone = (currentResults && currentResults.website_clone_check) ? currentResults.website_clone_check : null;
    if (clone && clone.available) {
        items.unshift(
            { label: "CLONE SIMILARITY", value: `${Math.round((clone.similarity || 0) * 100)}%`, flag: clone.likely_clone },
            { label: "OFFICIAL HOST", value: clone.reference_host || "—" },
        );
    }

    // add external threat feeds summary if present
    const feeds = (currentResults && currentResults.external_threat_feeds) ? currentResults.external_threat_feeds : null;
    if (Array.isArray(feeds) && feeds.length) {
        const flagged = feeds.filter(f => f && f.flagged).map(f => f.provider).join(", ");
        const available = feeds.filter(f => f && (f.available || f.source === "disabled")).map(f => f.provider).join(", ");
        items.unshift(
            { label: "THREAT FEEDS", value: available || "—" },
            { label: "FLAGGED BY", value: flagged || "None", flag: Boolean(flagged) },
        );
    }

    grid.innerHTML = items.map(item => `
    <div class="detail-item">
      <div class="detail-item-label">${item.label}</div>
      <div class="detail-item-value ${item.flag ? "text-high" : ""}">${escHtml(String(item.value))}</div>
    </div>
  `).join("");
}

function renderWhois(data) {
    const grid = document.getElementById("whoisGrid");
    const items = [
        { label: "REGISTRAR", value: data.registrar || "Unknown" },
        { label: "WHOIS STATUS", value: data.whois_flag || "—", flag: data.whois_flag === "Suspicious" },
        {
            label: "PRIVACY", value: data.privacy_protected ? "Protected" : "Public",
            flag: data.privacy_protected
        },
        {
            label: "DOMAIN AGE", value: data.domain_age || "Unknown",
            flag: (data.domain_age_days || 9999) < 90
        },
        { label: "CREATED", value: data.creation_date || "—" },
        {
            label: "TLD", value: `.${data.features?.tld || "?"}`,
            flag: data.features?.suspicious_tld
        },
    ];

    grid.innerHTML = items.map(item => `
    <div class="detail-item">
      <div class="detail-item-label">${item.label}</div>
      <div class="detail-item-value ${item.flag ? "text-high" : ""}">${escHtml(String(item.value))}</div>
    </div>
  `).join("");
}

function renderDetection(data) {
    const list = document.getElementById("detectionList");

    const signals = [
        {
            name: "TYPOSQUATTING",
            active: data.typosquatting?.detected,
            detail: data.typosquatting?.detected
                ? `Closest brand: <strong>${escHtml(data.typosquatting.closest_brand || "?")}</strong>
           — JW: ${(data.typosquatting.jaro_winkler_score * 100).toFixed(1)}%
           — Edit distance: ${data.typosquatting.edit_distance}`
                : `Closest: ${escHtml(data.typosquatting?.closest_brand || "?")}
           (JW: ${((data.typosquatting?.jaro_winkler_score || 0) * 100).toFixed(1)}%)`,
            score: ((data.typosquatting?.jaro_winkler_score || 0) * 100).toFixed(0),
        },
        {
            name: "HOMOGLYPH ATTACK",
            active: data.homoglyph?.detected,
            detail: data.homoglyph?.detected
                ? `${data.homoglyph.count} suspicious char(s). ` +
                (data.homoglyph.has_digit_substitution ? "Digit substitution detected. " : "") +
                `Normalized: <code>${escHtml(data.homoglyph.normalized_domain || "?")}</code>`
                : "No Unicode confusable characters detected.",
            score: data.homoglyph?.count || 0,
        },
        {
            name: "COMBO-SQUATTING",
            active: data.combosquatting?.detected,
            detail: data.combosquatting?.detected
                ? `Brand(s): <strong>${(data.combosquatting.matched_brands || []).join(", ")}</strong>
           — Keyword(s): <strong>${(data.combosquatting.matched_keywords || []).join(", ")}</strong>`
                : data.combosquatting?.matched_brands?.length
                    ? `Brand detected in domain (no suspicious keywords)`
                    : "No brand+keyword combo detected.",
            score: null,
        },
        {
            name: "SUSPICIOUS KEYWORDS",
            active: data.features?.has_suspicious_keywords,
            detail: data.features?.has_suspicious_keywords
                ? `Keywords found: <strong>${(data.features.matched_keywords || []).join(", ")}</strong>`
                : "No phishing keywords in domain.",
            score: null,
        },
        {
            name: "SUSPICIOUS TLD",
            active: data.features?.suspicious_tld,
            detail: data.features?.suspicious_tld
                ? `TLD <strong>.${escHtml(data.features.tld || "?")}</strong> is commonly used in phishing.`
                : `TLD .${escHtml(data.features?.tld || "?")} appears legitimate.`,
            score: null,
        },
        {
            name: "WHOIS FLAGS",
            active: data.whois_flag === "Suspicious",
            detail: data.whois_flag === "Suspicious"
                ? `Domain age: ${data.domain_age}. Registrar: ${escHtml(data.registrar || "?")}.`
                : `Domain appears established. Registrar: ${escHtml(data.registrar || "?")}.`,
            score: null,
        },
    ];

    list.innerHTML = signals.map(sig => {
        const cls = sig.active ? "active" : "clean";
        const statCls = sig.active ? "status-active" : "status-clean";
        const statLbl = sig.active ? "!" : "✓";

        return `
      <div class="detection-item ${cls}">
        <div class="detection-status ${statCls}">${statLbl}</div>
        <div class="detection-content">
          <div class="detection-name">${sig.name}</div>
          <div class="detection-detail">${sig.detail}</div>
        </div>
        ${sig.score !== null
                ? `<div class="detection-score ${sig.active ? "text-high" : "text-low"}">${sig.score}%</div>`
                : ""}
      </div>
    `;
    }).join("");
}

function renderFeatures(features) {
    const grid = document.getElementById("featuresGrid");

    const pills = [
        { label: "LENGTH", value: features.length || 0, flag: (features.length || 0) > 20 },
        { label: "DIGITS", value: features.digit_count || 0, flag: (features.digit_count || 0) > 2 },
        {
            label: "DIGIT RATIO", value: `${((features.digit_ratio || 0) * 100).toFixed(0)}%`,
            flag: (features.digit_ratio || 0) > 0.2
        },
        { label: "HYPHENS", value: features.hyphen_count || 0, flag: (features.hyphen_count || 0) >= 2 },
        { label: "SUBDOMAINS", value: features.subdomain_count || 0, flag: (features.subdomain_count || 0) >= 2 },
        { label: "ENTROPY", value: (features.entropy || 0).toFixed(2), flag: (features.entropy || 0) > 3.5 },
        { label: "IP-LIKE", value: features.is_ip_like ? "YES" : "NO", flag: features.is_ip_like },
        { label: "SUSP. TLD", value: features.suspicious_tld ? "YES" : "NO", flag: features.suspicious_tld },
    ];

    grid.innerHTML = pills.map(p => `
    <div class="feature-pill ${p.flag ? "flagged" : ""}">
      <div class="feature-pill-label">${p.label}</div>
      <div class="feature-pill-value">${escHtml(String(p.value))}</div>
    </div>
  `).join("");
}

function renderBreakdown(breakdown) {
    const list = document.getElementById("breakdownList");
    const total = Object.values(breakdown).reduce((s, v) => s + v, 0) || 1;

    const labels = {
        typosquatting: "TYPOSQUATTING",
        homoglyph: "HOMOGLYPH",
        digit_substitution: "DIGIT SUBSTITUTION",
        combosquatting: "COMBO-SQUATTING",
        brand_in_domain: "BRAND IN DOMAIN",
        near_match: "NEAR BRAND MATCH",
        domain_features: "DOMAIN FEATURES",
        whois: "WHOIS SIGNALS",
        dns: "DNS SIGNALS",
        ssl: "SSL SIGNALS",
        threat_intel: "THREAT INTEL",
    };

    const rows = Object.entries(breakdown)
        .filter(([, v]) => v > 0)
        .sort(([, a], [, b]) => b - a);

    if (rows.length === 0) {
        list.innerHTML = `<div style="color:var(--text-muted);font-family:var(--font-mono);font-size:12px;">
      No significant risk factors detected.
    </div>`;
        return;
    }

    list.innerHTML = rows.map(([key, val]) => `
    <div class="breakdown-row">
      <span class="breakdown-label">${labels[key] || key.toUpperCase()}</span>
      <div class="breakdown-bar-wrap">
        <div class="breakdown-bar" style="width:0%" data-width="${(val / total * 100).toFixed(0)}%"></div>
      </div>
      <span class="breakdown-val">+${val.toFixed(0)}</span>
    </div>
  `).join("");

    // Animate bars after render
    setTimeout(() => {
        list.querySelectorAll(".breakdown-bar").forEach(bar => {
            bar.style.width = bar.dataset.width;
        });
    }, 50);
}

function renderML(ml) {
    const section = document.getElementById("mlSection");
    const el = document.getElementById("mlResult");

    const data = currentResults; // access full response

    if (!ml || !ml.available) {
        el.innerHTML = `
        <div class="ml-unavailable">
            ML model unavailable — using rule-based scoring only.
        </div>`;
        return;
    }

    const rfColor = ml.ml_verdict === "Phishing" ? "text-high glow-red"
        : ml.ml_verdict === "Legitimate" ? "text-low glow-green"
        : "text-medium";

    const xgb = data.xgb || {};
    const hybridScore = data.hybrid_score ?? data.risk_score;
    const hybridLevel = data.hybrid_risk_level ?? data.risk_level;
    const ensemble = data.ensemble_ml || {};

    el.innerHTML = `
        <div style="margin-bottom:12px;">
            <div class="ml-verdict ${rfColor}">
                RF: ${ml.ml_verdict.toUpperCase()}
            </div>
            <div class="ml-prob">
                Score: <strong>${ml.ml_score?.toFixed(1)}%</strong>
                &nbsp;·&nbsp; Confidence: <strong>${ml.confidence?.toFixed(1)}%</strong>
            </div>
        </div>

        <div style="margin-bottom:12px;">
            <div class="ml-verdict text-yellow">
                XGB: ${(xgb.xgb_verdict || "N/A").toUpperCase()}
            </div>
            <div class="ml-prob">
                Score: <strong>${xgb.xgb_score ? xgb.xgb_score.toFixed(1) + "%" : "N/A"}</strong>
            </div>
        </div>

        ${ensemble.model_count > 0 ? `
        <div style="margin-bottom:12px; border-top:1px solid #444; padding-top:10px;">
            <div class="ml-verdict" style="color:#06b6d4;">
                ENSEMBLE: ${(ensemble.ensemble_verdict || "N/A").toUpperCase()}
            </div>
            <div class="ml-prob">
                Score: <strong>${ensemble.ensemble_score ?? "N/A"}%</strong>
                &nbsp;·&nbsp; Models: <strong>${ensemble.model_count}</strong>
                &nbsp;·&nbsp; Agreement: <strong>${ensemble.model_agreement}%</strong>
            </div>
            <div class="ml-prob" style="font-size:10px; color:#555;">
                ${ensemble.available_models ? ensemble.available_models.join(", ") : ""}
            </div>
        </div>
        ` : ""}

        <div style="border-top:1px solid #444; padding-top:10px;">
            <div class="ml-verdict text-high">
                HYBRID: ${hybridLevel.toUpperCase()}
            </div>
            <div class="ml-prob">
                Final Score: <strong>${hybridScore}%</strong>
            </div>
        </div>
    `;
}
// ──────────────────────────────────────────────────────────────────────────────
// ALERT SYSTEM
// ──────────────────────────────────────────────────────────────────────────────
function triggerAlert(data) {
    // Console alert
    console.warn(
        `%c⚠ HIGH RISK DOMAIN DETECTED\n` +
        `Domain: ${data.domain}\n` +
        `Score: ${(data.score ?? data.risk_score ?? "?")}/100\n` +
        `Attack: ${data.attack_type}\n` +
        `WHOIS: ${data.whois_flag}`,
        "color:#ff3d6e; font-size:14px; font-weight:bold;"
    );

    // UI banner
    const existing = document.getElementById("alertBanner");
    if (existing) existing.remove();

    const banner = document.createElement("div");
    banner.id = "alertBanner";
    banner.className = "alert-banner";
    banner.innerHTML = `
    <span class="alert-icon">⚠</span>
    <span>HIGH RISK ALERT — ${escHtml(data.domain)} — ${escHtml(data.attack_type)} DETECTED
      (Score: ${(data.score ?? data.risk_score ?? "?")}/100)</span>
  `;

    const resultsPanel = document.getElementById("resultsPanel");
    resultsPanel.insertBefore(banner, resultsPanel.firstChild);
}

// ──────────────────────────────────────────────────────────────────────────────
// REAL-TIME MONITORING SIMULATION
// ──────────────────────────────────────────────────────────────────────────────
const MONITOR_DOMAINS = [
    "paypa1.com", "g00gle.com", "amazon-secure.tk",
    "microsoft-support.xyz", "faceboook.com",
];

function startMonitorSimulation() {
    // Every 30s, silently check a random "monitored" domain and log
    monitorInterval = setInterval(async () => {
        const domain = MONITOR_DOMAINS[Math.floor(Math.random() * MONITOR_DOMAINS.length)];
        try {
            const res = await fetch(`${CONFIG.apiBase}/analyze-domain`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ domain, inspect_website: false }),
                signal: AbortSignal.timeout(5000),
            });
            if (res.ok) {
                const data = await res.json();
                if ((data.hybrid_risk_level || data.risk_level) === "High") {
                    console.info(
                        `%c[MONITOR] ${domain} → ${data.risk_level} (${(data.score ?? data.risk_score ?? "?")}/100) — ${data.attack_type}`,
                        "color:#ffd166;"
                    );
                }
            }
        } catch { /* silently skip */ }
    }, CONFIG.monitorInterval);
}

// ──────────────────────────────────────────────────────────────────────────────
// RESET / UI HELPERS
// ──────────────────────────────────────────────────────────────────────────────
function resetUI() {
    hideResults();
    document.getElementById("domainInput").value = "";
    document.getElementById("domainInput").focus();
    const banner = document.getElementById("alertBanner");
    if (banner) banner.remove();
    window.scrollTo({ top: 0, behavior: "smooth" });
}

function showLoader() {
    document.getElementById("loader").style.display = "flex";
    document.getElementById("analyzeBtn").disabled = true;
    document.getElementById("loaderText").textContent = "SCANNING...";
    document.getElementById("loaderSteps").textContent = "";
    document.getElementById("examplesSection").style.display = "none";
}

function hideLoader() {
    document.getElementById("loader").style.display = "none";
    document.getElementById("analyzeBtn").disabled = false;
}

function hideResults() {
    document.getElementById("resultsPanel").style.display = "none";
}

function showError(msg) {
    const el = document.getElementById("errorMsg");
    el.textContent = `⚠  ${msg}`;
    el.style.display = "block";
}

function hideError() {
    document.getElementById("errorMsg").style.display = "none";
}

// ──────────────────────────────────────────────────────────────────────────────
// UTILITIES
// ──────────────────────────────────────────────────────────────────────────────
function escHtml(str) {
    const div = document.createElement("div");
    div.appendChild(document.createTextNode(String(str)));
    return div.innerHTML;
}

function riskToColor(level) {
    switch (level) {
        case "Critical": return "var(--red)";
        case "High": return "var(--red)";
        case "Medium": return "var(--yellow)";
        default: return "var(--green)";
    }
}

function riskToGlow(level) {
    switch (level) {
        case "Critical": return "red";
        case "High": return "red";
        case "Medium": return "yellow";
        default: return "green";
    }
}
function triggerHighAlert(data) {
    // 🔊 Play sound
    const audio = document.getElementById("alertSound");
    if (audio) {
        audio.currentTime = 0;
        audio.play().catch(() => {});
    }

    // 🚨 Create big alert popup
    const alertBox = document.createElement("div");
    alertBox.className = "huge-alert";

    alertBox.innerHTML = `
        <div class="alert-content">
            🚨 HIGH RISK DOMAIN DETECTED 🚨<br><br>
            Domain: <b>${data.domain}</b><br>
            Score: <b>${(data.score ?? data.risk_score ?? "?")}%</b><br>
            Type: <b>${data.attack_type}</b><br><br>
            ⚠ POSSIBLE PHISHING ATTACK ⚠
        </div>
    `;

    document.body.appendChild(alertBox);

    // Remove after 5 sec
    setTimeout(() => {
        alertBox.remove();
    }, 5000);
}