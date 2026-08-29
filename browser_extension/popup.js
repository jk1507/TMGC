/**
 * RETRO_INTEL Browser Extension - Popup Script
 * Connects to the RETRO_INTEL backend API to scan domains in real-time.
 */

const API_URL = "http://127.0.0.1:8000/api/v1/analyze";

// DOM elements
const urlInput = document.getElementById("urlInput");
const scanBtn = document.getElementById("scanBtn");
const scanCurrentBtn = document.getElementById("scanCurrentBtn");
const resultSection = document.getElementById("resultSection");
const loadingSection = document.getElementById("loadingSection");
const errorSection = document.getElementById("errorSection");
const scoreDisplay = document.getElementById("scoreDisplay");
const scoreValue = document.getElementById("scoreValue");
const scoreVerdict = document.getElementById("scoreVerdict");
const findingsList = document.getElementById("findingsList");

// Initialize
document.addEventListener("DOMContentLoaded", () => {
  // Load last scanned URL from storage
  chrome.storage.local.get(["lastUrl"], (data) => {
    if (data.lastUrl) {
      urlInput.value = data.lastUrl;
    }
  });

  // Check current tab URL
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    if (tabs[0] && tabs[0].url) {
      try {
        const url = new URL(tabs[0].url);
        if (url.protocol === "http:" || url.protocol === "https:") {
          urlInput.placeholder = `Current: ${url.hostname}`;
        }
      } catch (e) {}
    }
  });
});

// Scan button
scanBtn.addEventListener("click", () => {
  const domain = urlInput.value.trim();
  if (!domain) return;
  scanDomain(domain);
});

// Scan current tab
scanCurrentBtn.addEventListener("click", () => {
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    if (tabs[0] && tabs[0].url) {
      try {
        const url = new URL(tabs[0].url);
        const domain = url.hostname;
        urlInput.value = domain;
        scanDomain(domain);
      } catch (e) {
        showError("Could not extract domain from current tab");
      }
    }
  });
});

// Enter key
urlInput.addEventListener("keydown", (e) => {
  if (e.key === "Enter") {
    scanBtn.click();
  }
});

// Main scan function
async function scanDomain(domain) {
  // Clean domain
  domain = domain.replace(/^https?:\/\//, "").replace(/\/.*$/, "").trim();

  // Save to storage
  chrome.storage.local.set({ lastUrl: domain });

  // Show loading
  showLoading(true);
  showError("");
  resultSection.classList.remove("visible");

  try {
    const response = await fetch(API_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: domain, deep_scan: false }),
    });

    if (!response.ok) {
      const detail = await response.json().catch(() => ({}));
      throw new Error(detail.detail || `HTTP ${response.status}`);
    }

    const data = await response.json();
    displayResults(data);
  } catch (err) {
    showError(`Scan failed: ${err.message}. Is the RETRO_INTEL backend running?`);
  } finally {
    showLoading(false);
  }
}

// Display results
function displayResults(data) {
  const score = data.risk_score || 0;

  // Score display
  scoreValue.textContent = `${score}/100`;

  // Verdict and color class
  let verdict, cls;
  if (score >= 71) {
    verdict = "CRITICAL / PHISHING";
    cls = "critical";
  } else if (score >= 46) {
    verdict = "HIGH RISK";
    cls = "high";
  } else if (score >= 26) {
    verdict = "SUSPICIOUS";
    cls = "medium";
  } else if (score >= 11) {
    verdict = "LOW RISK";
    cls = "low";
  } else {
    verdict = "SAFE / TRUSTED";
    cls = "safe";
  }

  scoreVerdict.textContent = verdict;
  scoreDisplay.className = `score-display ${cls}`;

  // Details
  document.getElementById("detailDomain").textContent = data.domain || "--";
  document.getElementById("detailIP").textContent = data.ip_address || data.target_ip || "--";
  document.getElementById("detailSSL").textContent = data.parsed_meta?.ssl_issuer || "--";
  document.getElementById("detailAge").textContent = data.parsed_meta?.domain_age || "--";
  document.getElementById("detailRegistrar").textContent = data.parsed_meta?.registrar || "--";

  // Findings
  findingsList.innerHTML = "";
  const findings = data.findings || [];
  if (findings.length === 0) {
    findingsList.innerHTML = '<div class="finding-item info">No findings detected</div>';
  } else {
    findings.slice(0, 15).forEach((finding) => {
      const item = document.createElement("div");
      item.className = `finding-item ${getSeverityClass(finding)}`;
      item.textContent = finding;
      findingsList.appendChild(item);
    });
  }

  resultSection.classList.add("visible");
}

// Helper: extract severity from finding text
function getSeverityClass(finding) {
  const upper = finding.toUpperCase();
  if (upper.startsWith("CRITICAL")) return "critical";
  if (upper.startsWith("HIGH")) return "high";
  if (upper.startsWith("MEDIUM")) return "medium";
  if (upper.startsWith("LOW")) return "low";
  return "info";
}

// Show/hide loading
function showLoading(show) {
  loadingSection.style.display = show ? "block" : "none";
  scanBtn.disabled = show;
  scanCurrentBtn.disabled = show;
}

// Show error
function showError(msg) {
  if (msg) {
    errorSection.style.display = "block";
    document.getElementById("errorMsg").textContent = msg;
  } else {
    errorSection.style.display = "none";
  }
}
