/**
 * RETRO_INTEL Browser Extension - Content Script
 * Runs on every page to detect phishing indicators in the DOM.
 */

(function () {
  "use strict";

  // Prevent multiple injections
  if (window.__retro_intel_injected) return;
  window.__retro_intel_injected = true;

  const findings = [];

  // --- 1. Check for credential harvesting forms ---
  function checkForms() {
    const forms = document.querySelectorAll("form");
    forms.forEach((form) => {
      const passwordInput = form.querySelector('input[type="password"]');
      if (!passwordInput) return;

      const action = form.getAttribute("action") || "";
      const pageDomain = window.location.hostname;

      // Check if form action targets a different domain
      if (action.startsWith("http")) {
        try {
          const actionDomain = new URL(action).hostname;
          if (actionDomain !== pageDomain) {
            findings.push({
              type: "critical",
              message: `Password form submits to external domain: ${actionDomain}`,
            });
          }
        } catch (e) {}
      }

      // Check for suspicious form attributes
      if (form.method && form.method.toLowerCase() === "get" && passwordInput) {
        findings.push({
          type: "high",
          message: "Password submitted via GET method (credentials visible in URL)",
        });
      }
    });
  }

  // --- 2. Check for iframes ---
  function checkIframes() {
    const iframes = document.querySelectorAll("iframe");
    iframes.forEach((iframe) => {
      const src = iframe.src || "";
      if (src && src.startsWith("http")) {
        try {
          const iframeDomain = new URL(src).hostname;
          if (iframeDomain !== window.location.hostname) {
            findings.push({
              type: "medium",
              message: `Cross-origin iframe detected: ${iframeDomain}`,
            });
          }
        } catch (e) {}
      }

      // Hidden iframes
      const style = window.getComputedStyle(iframe);
      if (
        style.display === "none" ||
        style.visibility === "hidden" ||
        parseInt(style.width) < 2 ||
        parseInt(style.height) < 2
      ) {
        findings.push({
          type: "high",
          message: "Hidden iframe detected (possible keylogger or data exfiltration)",
        });
      }
    });
  }

  // --- 3. Check for suspicious scripts ---
  function checkScripts() {
    const scripts = document.querySelectorAll("script");
    let inlineScriptCount = 0;
    let obfuscationCount = 0;

    scripts.forEach((script) => {
      const code = script.textContent || "";

      // Count inline scripts
      if (code.trim().length > 0) {
        inlineScriptCount++;
      }

      // Check for obfuscation patterns
      if (/(?:eval|document\.write|unescape|String\.fromCharCode)\s*\(/.test(code)) {
        obfuscationCount++;
      }
    });

    if (obfuscationCount >= 3) {
      findings.push({
        type: "high",
        message: `Script obfuscation detected (${obfuscationCount} suspicious scripts)`,
      });
    }

    if (inlineScriptCount > 20) {
      findings.push({
        type: "low",
        message: `High number of inline scripts (${inlineScriptCount})`,
      });
    }
  }

  // --- 4. Check page content for phishing keywords ---
  function checkContent() {
    const body = document.body ? document.body.innerText : "";
    const lower = body.toLowerCase();

    const phishingPhrases = [
      "verify your account",
      "confirm your password",
      "update your payment",
      "account suspended",
      "unusual activity detected",
      "click here to verify",
      "your account will be",
      "act now",
      "limited time",
    ];

    let hitCount = 0;
    for (const phrase of phishingPhrases) {
      if (lower.includes(phrase)) {
        hitCount++;
      }
    }

    if (hitCount >= 3) {
      findings.push({
        type: "high",
        message: `Multiple phishing phrases detected in page content (${hitCount})`,
      });
    } else if (hitCount >= 1) {
      findings.push({
        type: "low",
        message: `Possible phishing language detected (${hitCount} phrase matches)`,
      });
    }
  }

  // --- 5. Check for popups / new windows ---
  function checkPopups() {
    // Override window.open to detect popup attempts
    const originalOpen = window.open;
    window.open = function (...args) {
      findings.push({
        type: "medium",
        message: "Page attempted to open a popup/new window",
      });
      return originalOpen.apply(this, args);
    };
  }

  // --- Run all checks ---
  try {
    checkForms();
    checkIframes();
    checkScripts();
    checkContent();
    checkPopups();
  } catch (e) {
    // Silently fail
  }

  // Store findings for popup to retrieve
  if (findings.length > 0) {
    chrome.runtime.sendMessage({
      type: "contentFindings",
      domain: window.location.hostname,
      findings: findings,
    });
  }

  // Store in session storage for popup access
  try {
    const key = `retro_intel_${window.location.hostname}`;
    sessionStorage.setItem(key, JSON.stringify({
      findings,
      url: window.location.href,
      timestamp: Date.now(),
    }));
  } catch (e) {}
})();
