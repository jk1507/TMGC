/**
 * RETRO_INTEL Browser Extension - Background Service Worker
 * Performs real-time URL checking and threat detection.
 */

const API_URL = "http://127.0.0.1:8000/api/v1/analyze";
const CACHE_TTL_MS = 5 * 60 * 1000; // 5 minutes
const THREAT_THRESHOLD = 46; // High risk threshold

// In-memory cache for recent scans
const scanCache = new Map();

// Listen for navigation events
chrome.webNavigation.onCompleted.addListener(
  async (details) => {
    if (details.frameId !== 0) return; // Only main frame
    if (!details.url.startsWith("http")) return;

    try {
      const url = new URL(details.url);
      const domain = url.hostname;

      // Check cache first
      const cached = scanCache.get(domain);
      if (cached && Date.now() - cached.timestamp < CACHE_TTL_MS) {
        if (cached.score >= THREAT_THRESHOLD) {
          showWarningBadge(domain, cached.score);
        }
        return;
      }

      // Perform quick scan
      const score = await quickScan(domain);
      scanCache.set(domain, { score, timestamp: Date.now() });

      if (score >= THREAT_THRESHOLD) {
        showWarningBadge(domain, score);
        sendNotification(domain, score);
      } else {
        clearBadge();
      }
    } catch (e) {
      // Silently fail - don't disrupt browsing
    }
  },
  { url: [{ schemes: ["http", "https"] }] }
);

// Quick scan (no deep analysis, fast response)
async function quickScan(domain) {
  try {
    const response = await fetch(API_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: domain, deep_scan: false }),
      signal: AbortSignal.timeout(8000), // 8 second timeout
    });

    if (!response.ok) return 0;
    const data = await response.json();
    return data.risk_score || 0;
  } catch (e) {
    return 0;
  }
}

// Show warning badge on extension icon
function showWarningBadge(domain, score) {
  let color, text;
  if (score >= 71) {
    color = "#FF0000";
    text = "!";
  } else if (score >= 46) {
    color = "#FF6600";
    text = "!";
  } else {
    color = "#FFAA00";
    text = "?";
  }

  chrome.action.setBadgeBackgroundColor({ color });
  chrome.action.setBadgeText({ text });
}

// Clear badge
function clearBadge() {
  chrome.action.setBadgeText({ text: "" });
}

// Send notification for high-risk domains
function sendNotification(domain, score) {
  let severity;
  if (score >= 71) severity = "CRITICAL";
  else if (score >= 46) severity = "HIGH RISK";
  else severity = "SUSPICIOUS";

  chrome.notifications.create({
    type: "basic",
    iconUrl: "icons/icon128.png",
    title: `RETRO_INTEL: ${severity}`,
    message: `${domain} has a risk score of ${score}/100. Click to view details.`,
    priority: 2,
  });
}

// Handle messages from content scripts and popup
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.type === "scan") {
    quickScan(request.domain).then((score) => {
      sendResponse({ score });
    });
    return true; // async response
  }

  if (request.type === "getCache") {
    const cached = scanCache.get(request.domain);
    sendResponse({ cached });
    return true;
  }
});

// Clean old cache entries periodically
setInterval(() => {
  const now = Date.now();
  for (const [domain, data] of scanCache.entries()) {
    if (now - data.timestamp > CACHE_TTL_MS * 2) {
      scanCache.delete(domain);
    }
  }
}, 60000); // every minute
