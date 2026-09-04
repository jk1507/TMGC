import React, { useMemo, useRef, useState } from "react";
import PremiumDashboard, { getTrustScore } from "./PremiumDashboard.jsx";
import { RAW_TABS } from "./dashboardShared.jsx";
import CyberGlobe from "./CyberGlobe.jsx";
import { CyberStyles } from "./cyberTheme.jsx";

const isDev = import.meta.env.DEV;

// API URL configuration:
// - Development: Use Vite proxy (requests go to /api/... which proxies to backend)
// - Production: Use VITE_API_URL env var (set in Vercel) OR fallback to relative /api/
const API_BASE = isDev ? "" : (import.meta.env.VITE_API_URL || "");
const API_URL = `${API_BASE}/api/v1/analyze`;
const AI_ANALYSIS_API = `${API_BASE}/api/v1/ai-analysis`;
const KEYWORDS = [
  "CRITICAL",
  "HIGH RISK",
  "MEDIUM RISK",
  "LOW RISK",
  "SAFE",
  "SUSPICIOUS",
  "TYPOSQUATTING",
  "PHISHING",
  "MALWARE",
  "SSL",
  "EXPOSED PORT",
  "DEAD HOST",
  "XSS",
  "CLICKJACKING",
];

const pipelineLogs = [
  ">> NORMALIZING TARGET VECTOR...",
  ">> EXECUTING DNS TARGET MAP: dig A +short...",
  ">> ENUMERATING MAIL EXCHANGE VECTORS...",
  ">> TRACING INFRASTRUCTURE WHOIS ON PRIMARY IP...",
  ">> ASSESSING DOMAIN LIFECYCLE WHOIS...",
  ">> COMPILING CRYPTO INTEGRITY ROOTS...",
  ">> PROBING WEBSERVER HEADER POSTURE...",
  ">> LAUNCHING COMMON PORT RECON CHECK...",
  ">> STREAMING RAW MATRIX INTO AI CORE...",
];

const NAV_ITEMS = [
  { id: "dashboard", label: "Dashboard", icon: "grid" },
  { id: "threat-analysis", label: "Threat Analysis", icon: "shield" },
  { id: "domain-intelligence", label: "Domain Intelligence", icon: "globe" },
  { id: "ip-network", label: "IP & Network", icon: "network" },
  { id: "whois-lookup", label: "WHOIS Lookup", icon: "search" },
  { id: "ssl-analysis", label: "SSL/TLS Analysis", icon: "lock" },
  { id: "dns-records", label: "DNS Records", icon: "dns" },
  { id: "content-analysis", label: "Content Analysis", icon: "file" },
  { id: "reputation", label: "Reputation Lookup", icon: "star" },
  { id: "entity-attribution", label: "Entity Attribution", icon: "user" },
  { id: "brand-impersonation", label: "Brand Impersonation", icon: "brand" },
  { id: "email-analysis", label: "Email Phishing (BERT)", icon: "email" },
  { id: "cnn-analysis", label: "CNN Visual Analysis", icon: "visual" },
  { id: "gnn-analysis", label: "GNN Graph Analysis", icon: "graph" },
  { id: "transformer-ensemble", label: "Transformer Ensemble", icon: "ensemble" },
  { id: "security-alerts", label: "Security Alerts", icon: "alert" },
  { id: "reports", label: "Reports", icon: "report" },
  { id: "saved-scans", label: "Saved Scans", icon: "bookmark" },
  { id: "settings", label: "Settings", icon: "settings" },
];

const TMGC_VERSION = "v2.0.0 TMGC";

function App() {
  const [target, setTarget] = useState("example.com");
  const [user, setUser] = useState(() => {
    const session = localStorage.getItem("tmgc_session");
    const userData = localStorage.getItem("tmgc_user");
    if (session && userData) {
      return JSON.parse(userData);
    }
    localStorage.removeItem("tmgc_user");
    localStorage.removeItem("tmgc_session");
    return null;
  });
  const [logs, setLogs] = useState(["RETRO_INTEL SHELL READY.", "AWAITING TARGET INPUT..."]);
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [activeTab, setActiveTab] = useState("dig");
  const [currentView, setCurrentView] = useState("dashboard");
  const [aiReport, setAiReport] = useState(null);
  const [loadingAI, setLoadingAI] = useState(false);
  const [exportOpen, setExportOpen] = useState(false);
  const [reportModalOpen, setReportModalOpen] = useState(false);
  const [scanHistory, setScanHistory] = useState(() => {
    try {
      return JSON.parse(localStorage.getItem("tmgc_scan_history") || "[]");
    } catch {
      return [];
    }
  });
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [deepScan, setDeepScan] = useState(true);
  const [scanMeta, setScanMeta] = useState({ startedAt: null, completedAt: null, durationMs: null });
  const [mlInferenceMs, setMlInferenceMs] = useState(null);
  const exportRef = useRef(null);
  
  // New feature states
  const [emailText, setEmailText] = useState("");
  const [emailResult, setEmailResult] = useState(null);
  const [loadingEmail, setLoadingEmail] = useState(false);
  
  const [cnnResult, setCnnResult] = useState(null);
  const [loadingCNN, setLoadingCNN] = useState(false);
  
  const [gnnResult, setGnnResult] = useState(null);
  const [loadingGNN, setLoadingGNN] = useState(false);
  
  const [ensembleResult, setEnsembleResult] = useState(null);
  const [loadingEnsemble, setLoadingEnsemble] = useState(false);

  const data = useMemo(() => normalizeResult(result), [result]);
  const riskScore = data?.risk_score || 0;
  const highRisk = riskScore >= 46;
  
  // Use backend classification if available, otherwise compute locally
  const backendClassification = data?.score_components?.classification_v2;
  const backendSeverity = data?.score_components?.classification_severity;
  
  const verdict = backendClassification
    ? (backendSeverity === "critical" ? "☠️ CRITICAL / PHISHING"
        : backendSeverity === "high" ? "🔴 HIGH RISK"
        : backendSeverity === "suspicious" ? "🟠 SUSPICIOUS"
        : backendSeverity === "low" ? "🟡 LOW RISK"
        : "✅ SAFE VERIFIED")
    : riskScore >= 71
      ? "☠️ CRITICAL / PHISHING"
      : riskScore >= 46
      ? "🔴 HIGH RISK"
      : riskScore >= 26
      ? "🟠 SUSPICIOUS"
      : riskScore >= 11
      ? "🟡 LOW RISK"
      : "✅ SAFE / TRUSTED";
  const accent = highRisk ? "border-red-500 text-red-400 shadow-[0_0_24px_rgba(239,68,68,0.45)]" : "border-green-500 text-green-400 shadow-[0_0_24px_rgba(34,197,94,0.35)]";
 const headerRows =
  data?.security_header_details ||
  defaultHeaderRows();
  if (!user) {
    return <AuthScreen onAuthenticated={setUser} />;
  }

  function scrollToSection(sectionId) {
    setCurrentView(sectionId);
    setSidebarOpen(false);
    const node = document.getElementById(sectionId);
    if (node) node.scrollIntoView({ behavior: "smooth", block: "start" });
  }

  function shareReport() {
    if (!data) return;
    const summary = `TMGC Forensic Report — ${data.domain}\nRisk Score: ${data.risk_score}/100\nTrust Score: ${getTrustScore(data.risk_score)}/100`;
    if (navigator.share) {
      navigator.share({ title: "TMGC Forensic Report", text: summary, url: window.location.href }).catch(() => {});
      return;
    }
    navigator.clipboard?.writeText(summary).catch(() => {});
  }

  async function analyze() {
    const cleanTarget = target.trim();
    if (!cleanTarget) return;

    const startedAt = Date.now();
    setLoading(true);
    setError("");
    setResult(null);
    setAiReport(null);
    setMlInferenceMs(null);
    setScanMeta({ startedAt, completedAt: null, durationMs: null });
    setLogs([`RETRO_INTEL SHELL > TARGET=${cleanTarget}`]);

    pipelineLogs.forEach((line, index) => {
      window.setTimeout(() => {
        setLogs((current) => [...current, line]);
      }, 180 * (index + 1));
    });

    try {
      const fetchStart = performance.now();
      const response = await fetch(API_URL, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: cleanTarget, deep_scan: deepScan }),
      });

      if (!response.ok) {
        const detail = await response.json().catch(() => ({}));
        throw new Error(detail.detail || `Backend returned HTTP ${response.status}`);
      }

      const payload = await response.json();
      const totalMs = Math.round(performance.now() - fetchStart);
      setMlInferenceMs(totalMs);
      setResult({
        ...payload,
        timing: {
          ...(payload.timing || {}),
          frontend_total_ms: totalMs,
        },
      });
      setLogs((current) => [
        ...current,
        ">> AI CORE VERDICT RECEIVED.",
        `>> RISK SCORE LOCKED: ${payload.risk_score}/100`,
      ]);
      const historyEntry = {
        domain: payload.domain || cleanTarget,
        risk_score: payload.risk_score || 0,
        findings: payload.findings || [],
        completedAt: Date.now(),
      };
      setScanHistory((current) => {
        const next = [historyEntry, ...current.filter((s) => s.domain !== historyEntry.domain)].slice(0, 20);
        localStorage.setItem("tmgc_scan_history", JSON.stringify(next));
        return next;
      });
      // Auto-trigger detailed AI analysis after scan completes
      const autoRawContext = payload.raw_context || "";
      setTimeout(() => {
        // Only auto-run if user hasn't manually triggered it yet
        runAIAnalysis(autoRawContext);
      }, 500);
    } catch (analysisError) {
      setError(analysisError.message || "Analysis failed.");
      setLogs((current) => [...current, `!! PIPELINE FAILURE: ${analysisError.message}`]);
    } finally {
      setLoading(false);
      setScanMeta((current) => ({
        ...current,
        completedAt: Date.now(),
        durationMs: Date.now() - startedAt,
      }));
    }
  }

  async function runAIAnalysis(overrideRawContext) {
  const cleanTarget = target.trim();
  if (!cleanTarget) return;

  setLoadingAI(true);
  setError("");
  setAiReport(null);

  setLogs((current) => [
    ...current,
    ">> STREAMING RAW MATRIX INTO AI CORE...",
    ">> EXECUTING CONTEXTUAL THREAT REASONING...",
  ]);

  // Get raw_context: prefer explicit param, then state, then empty
  let rawContext = overrideRawContext || data?.raw_context || result?.raw_context || "";

  try {
    const response = await fetch(AI_ANALYSIS_API, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        url: cleanTarget,
        raw_context: rawContext,
      }),
    });

    if (!response.ok) {
      const detail = await response.json().catch(() => ({}));
      if (
  response.status === 429 ||
  String(detail.detail || "")
    .toLowerCase()
    .includes("quota")
) {
  throw new Error(
    "AI quota exhausted. Using ML + heuristic analysis only."
  );
}

if (
  response.status === 503 ||
  String(detail.detail || "")
    .toLowerCase()
    .includes("high demand")
) {
  throw new Error(
    "AI servers are under high demand. Please try again in a few minutes."
  );
}
throw new Error(
  detail.detail ||
  `Backend returned HTTP ${response.status}`
);
    }
  
    const payload = await response.json();

    setAiReport(payload);

    setLogs((current) => [
      ...current,
      ">> FALSE POSITIVE CHECK COMPLETE.",
      ">> AI ANALYSIS REPORT READY.",
    ]);
  } catch (err) {
    setError(err.message || "AI analysis failed.");

    setLogs((current) => [
      ...current,
      `!! AI CORE FAILURE: ${err.message}`,
    ]);
  } finally {
    setLoadingAI(false);
  }
}

  // Email Phishing Analysis (BERT)
  async function analyzeEmailPhishing() {
    if (!emailText.trim()) return;
    
    setLoadingEmail(true);
    setEmailResult(null);
    setError("");
    
    try {
      const response = await fetch(`${API_BASE}/api/v1/bert-analyze`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ text: emailText, model_type: "email" }),
      });
      
      if (!response.ok) {
        const detail = await response.json().catch(() => ({}));
        throw new Error(detail.detail || `Backend returned HTTP ${response.status}`);
      }
      
      const payload = await response.json();
      setEmailResult(payload);
    } catch (err) {
      setError(err.message || "Email analysis failed.");
    } finally {
      setLoadingEmail(false);
    }
  }

  // CNN Visual Analysis
  async function analyzeCNN() {
    if (!data) return;
    
    setLoadingCNN(true);
    setCnnResult(null);
    setError("");
    
    try {
      const response = await fetch(`${API_BASE}/api/v1/cnn-analyze`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          dom_features: buildCnnDomFeatures(data),
          visual_features: buildVisualFeatures(data),
        }),
      });
      
      if (!response.ok) {
        const detail = await response.json().catch(() => ({}));
        throw new Error(detail.detail || `Backend returned HTTP ${response.status}`);
      }
      
      const payload = await response.json();
      setCnnResult(payload);
    } catch (err) {
      setError(err.message || "CNN analysis failed.");
    } finally {
      setLoadingCNN(false);
    }
  }

  // GNN Graph Analysis
  async function analyzeGNN() {
    if (!data) return;
    
    setLoadingGNN(true);
    setGnnResult(null);
    setError("");
    
    try {
      const response = await fetch(`${API_BASE}/api/v1/gnn-analyze`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ graph_data: buildGraphFeatures(data) }),
      });
      
      if (!response.ok) {
        const detail = await response.json().catch(() => ({}));
        throw new Error(detail.detail || `Backend returned HTTP ${response.status}`);
      }
      
      const payload = await response.json();
      setGnnResult(payload);
    } catch (err) {
      setError(err.message || "GNN analysis failed.");
    } finally {
      setLoadingGNN(false);
    }
  }

  // Transformer Ensemble
  async function analyzeEnsemble() {
    if (!data) return;
    
    setLoadingEnsemble(true);
    setEnsembleResult(null);
    setError("");
    
    try {
      const response = await fetch(`${API_BASE}/api/v1/transformer-ensemble`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          email_text: emailText,
          dom_features: buildCnnDomFeatures(data),
          visual_features: buildVisualFeatures(data),
          graph_data: buildGraphFeatures(data),
          xgboost_result: data.ml_result || {},
        }),
      });
      
      if (!response.ok) {
        const detail = await response.json().catch(() => ({}));
        throw new Error(detail.detail || `Backend returned HTTP ${response.status}`);
      }
      
      const payload = await response.json();
      setEnsembleResult(payload);
    } catch (err) {
      setError(err.message || "Ensemble analysis failed.");
    } finally {
      setLoadingEnsemble(false);
    }
  }

  async function exportExcel() {
  if (!data) return;

  try {
    const XLSX = await import("xlsx");

    const workbook = XLSX.utils.book_new();

    // ==========================
    // 1. EXECUTIVE SUMMARY
    // ==========================
    const verdict =
      data.risk_score >= 90
        ? "CRITICAL / PHISHING"
        : data.risk_score >= 60
        ? "HIGH RISK"
        : data.risk_score >= 30
        ? "SUSPICIOUS"
        : "SAFE / TRUSTED";

    const summaryData = [
      ["RETRO_INTEL THREAT DOSSIER"],
      [],
      ["Target Domain", data.domain],
      ["Risk Score", `${data.risk_score}/100`],
      ["Verdict", verdict],
      ["Target IP", data.ip_address || "N/A"],
      ["Hosting Space", data.parsed_meta.hosting_space || "N/A"],
      ["Domain Age", data.parsed_meta.domain_age || "N/A"],
      ["ASN", data.parsed_meta.asn || "N/A"],
      ["Country", data.parsed_meta.country || "N/A"],
      ["HTTP Status", data.parsed_meta.http_status || "N/A"],
      ["SSL Issuer", data.parsed_meta.ssl_issuer || "N/A"],
      ["Generated At", new Date().toLocaleString()],
    ];

    const summarySheet =
      XLSX.utils.aoa_to_sheet(summaryData);

    XLSX.utils.book_append_sheet(
      workbook,
      summarySheet,
      "EXECUTIVE_SUMMARY"
    );

    // ==========================
    // 2. SECURITY HEADERS
    // ==========================
    const headerData = headerRows.map(
      (header) => ({
        HEADER: header.name,
        STATUS: header.status || (header.enabled ? "ENABLED" : "MISSING"),
        VALUE: header.value || "N/A",
        SEVERITY: header.strength || header.status || (header.enabled ? "SAFE" : "MEDIUM"),
        EVIDENCE: header.evidence || "N/A",
        RECOMMENDATION: header.recommendation || "N/A",
      })
    );

    const headerSheet =
      XLSX.utils.json_to_sheet(headerData);

    XLSX.utils.book_append_sheet(
      workbook,
      headerSheet,
      "SECURITY_HEADERS"
    );

    // ==========================
    // 3. ML ANALYSIS
    // ==========================
    const mlData = [
      ["MODEL", "XGBoost"],
      [
        "VERDICT",
        data.ml_result?.xgb_verdict || "N/A",
      ],
      [
        "ML SCORE",
        data.ml_result?.xgb_score || "N/A",
      ],
      [
        "MODEL AVAILABLE",
        data.ml_result?.xgb_available
          ? "YES"
          : "NO",
      ],
    ];

    const mlSheet =
      XLSX.utils.aoa_to_sheet(mlData);

    XLSX.utils.book_append_sheet(
      workbook,
      mlSheet,
      "ML_ANALYSIS"
    );

    // ==========================
    // 4. FINDINGS
    // ==========================
    const findingsData =
      data.findings.map((finding) => ({
        FINDING: finding,
      }));

    const findingsSheet =
      XLSX.utils.json_to_sheet(findingsData);

    XLSX.utils.book_append_sheet(
      workbook,
      findingsSheet,
      "FINDINGS"
    );

    // ==========================
    // 5. RAW EVIDENCE
    // ==========================
    const rawData = [];

    RAW_TABS.forEach((tab) => {
      rawData.push({
        COMMAND: tab.toUpperCase(),
        OUTPUT:
          data.raw_logs?.[tab] ||
          "NO DATA AVAILABLE",
      });
    });

    const rawSheet =
      XLSX.utils.json_to_sheet(rawData);

    XLSX.utils.book_append_sheet(
      workbook,
      rawSheet,
      "RAW_EVIDENCE"
    );

    // ==========================
    // 6. AI ANALYSIS
    // ==========================
    const aiSheet =
      XLSX.utils.aoa_to_sheet([
        [
          aiReport?.formatted_report ||
            data.ai_verdict ||
            "AI ANALYSIS NOT AVAILABLE",
        ],
      ]);

    XLSX.utils.book_append_sheet(
      workbook,
      aiSheet,
      "AI_ANALYSIS"
    );

    XLSX.writeFile(
      workbook,
      `threat_report_${data.domain}.xlsx`
    );
  } catch (err) {
    setError(
      `Excel export failed: ${err.message}`
    );
  }
}
  function exportJson() {
    if (!data) return;
    const payload = {
      domain: data.domain,
      risk_score: data.risk_score,
      ip_address: data.ip_address,
      parsed_meta: data.parsed_meta,
      findings: data.findings,
      score_components: data.score_components,
      ml_result: data.ml_result,
      security_headers: data.security_header_details,
      raw_logs: data.raw_logs,
      ai_verdict: data.ai_verdict,
      generated_at: new Date().toISOString(),
    };
    downloadBlob(`forensic_report_${data.domain}.json`, JSON.stringify(payload, null, 2), "application/json;charset=utf-8");
  }

  function exportRawTxt() {
    if (!data) return;
    const body = RAW_TABS.map((key) => {
      const label = key.toUpperCase();
      return `================ ${label} ================\n${data.raw_logs[key] || "N/A"}`;
    }).join("\n\n");
    downloadBlob(`terminal_dump_${data.domain}.txt`, body, "text/plain;charset=utf-8");
  }

  function exportMarkdown() {
    if (!data) return;
    const headers = headerRows
      .map((header) => `- [${header.status || (header.enabled ? "ENABLED" : "MISSING")}] ${header.name}${header.value ? `: ${header.value}` : ""}${header.evidence ? ` — ${header.evidence}` : ""}`)
      .join("\n");
    const commands = RAW_TABS.map((key) => `## ${key}\n\n\`\`\`text\n${data.raw_logs[key] || "N/A"}\n\`\`\``).join("\n\n");
    const markdown = `# RETRO_INTEL Threat Report: ${data.domain}

Risk Score: ${data.risk_score}/100
Target IP: ${data.ip_address || "N/A"}
Hosting Space: ${data.parsed_meta.hosting_space || "N/A"}
ASN: ${data.parsed_meta.asn || "N/A"}
Country: ${data.parsed_meta.country || "N/A"}
Registrar: ${data.parsed_meta.registrar || "N/A"}
Domain Age: ${data.parsed_meta.domain_age || "N/A"}
Created Date: ${data.parsed_meta.created_date || "N/A"}
HTTP Final Status: ${data.parsed_meta.http_status || "N/A"}
SSL Issuer: ${data.parsed_meta.ssl_issuer || "N/A"}

## Findings
${data.findings.map((finding) => `- ${finding}`).join("\n")}

## Security Headers
${headers}

## AI Evaluation
${data.ai_verdict}

## Raw Command Evidence
${commands}
`;

    downloadBlob(`threat_report_${data.domain}.md`, markdown, "text/markdown;charset=utf-8");
  }

  async function exportPdf() {
    if (!data) return;
    try {
      const { jsPDF } = await import("jspdf");
      const doc = new jsPDF({ unit: "pt", format: "a4" });
      const pageWidth = doc.internal.pageSize.getWidth();
      const pageHeight = doc.internal.pageSize.getHeight();
      let y = 64;

      const addPageIfNeeded = (height = 24) => {
        if (y + height > pageHeight - 54) {
          doc.addPage();
          y = 54;
        }
      };
      const heading = (text) => {
        addPageIfNeeded(36);
        doc.setFont("courier", "bold");
        doc.setTextColor(0, 120, 40);
        doc.setFontSize(14);
        doc.text(text, 42, y);
        y += 22;
      };
      const line = (text, size = 9) => {
        doc.setFont("courier", "normal");
        doc.setFontSize(size);
        const chunks = doc.splitTextToSize(String(text || "N/A"), pageWidth - 84);
        chunks.forEach((chunk) => {
          addPageIfNeeded(14);
          drawHighlightedPdfLine(doc, chunk, 42, y);
          y += 13;
        });
      };

      doc.setFillColor(0, 0, 0);
      doc.rect(0, 0, pageWidth, pageHeight, "F");
      doc.setFont("courier", "bold");
      doc.setTextColor(0, 210, 80);
      doc.setFontSize(22);
      doc.text("RETRO_INTEL", 42, y);
      y += 30;
      doc.setFontSize(13);
      doc.text("OSINT DOMAIN THREAT ANALYZER", 42, y);
      y += 34;
      line(`Target: ${data.domain}`, 11);
      line(`Risk Score: ${data.risk_score}/100`, 11);
      line(`Timestamp: ${new Date().toISOString()}`, 10);

      heading("Executive Summary");
      line(`IP: ${data.ip_address || "N/A"}`);
      line(`Hosting Space: ${data.parsed_meta.hosting_space || "N/A"}`);
      line(`ASN / Country: ${data.parsed_meta.asn || "N/A"} / ${data.parsed_meta.country || "N/A"}`);
      line(`Domain Age: ${data.parsed_meta.domain_age || "N/A"} (${data.parsed_meta.created_date || "N/A"})`);
      line(`SSL Issuer: ${data.parsed_meta.ssl_issuer || "N/A"}`);

      heading("Key Findings Table");
      data.findings.forEach((finding, index) => line(`${index + 1}. ${finding}`));

      heading("Threat Intelligence");
      line(data.ai_verdict);

      heading("Security Headers Table");
      headerRows.forEach((header) => line(`${header.name}: ${header.status || (header.enabled ? "ENABLED" : "MISSING")}${header.value ? ` | ${header.value}` : ""}${header.evidence ? ` | ${header.evidence}` : ""}`));

      heading("Risk Score");
      line(`${data.risk_score}/100`);

      heading("AI Verdict");
      line(data.ai_verdict);

      heading("Timestamp");
      line(new Date().toISOString());

      heading("Raw Log Appendix");
      RAW_TABS.forEach((key) => {
        line(`--- ${key.toUpperCase()} ---`);
        line(data.raw_logs[key] || "N/A", 8);
      });

      doc.save(`forensic_dossier_${data.domain}.pdf`);
    } catch (pdfError) {
      setError(`PDF export requires jsPDF. ${pdfError.message || ""}`.trim());
    }
  }

  return (
    <PremiumDashboard
      user={user}
      target={target}
      setTarget={setTarget}
      logs={logs}
      data={data}
      loading={loading}
      loadingAI={loadingAI}
      error={error}
      activeTab={activeTab}
      setActiveTab={setActiveTab}
      aiReport={aiReport}
      currentView={currentView}
      exportOpen={exportOpen}
      setExportOpen={setExportOpen}
      reportModalOpen={reportModalOpen}
      setReportModalOpen={setReportModalOpen}
      scanHistory={scanHistory}
      exportJson={exportJson}
      sidebarOpen={sidebarOpen}
      setSidebarOpen={setSidebarOpen}
      scanMeta={scanMeta}
      headerRows={headerRows}
      verdict={verdict}
      accent={accent}
      exportRef={exportRef}
      analyze={analyze}
      runAIAnalysis={runAIAnalysis}
      exportExcel={exportExcel}
      exportPdf={exportPdf}
      exportRawTxt={exportRawTxt}
      exportMarkdown={exportMarkdown}
      shareReport={shareReport}
      scrollToSection={scrollToSection}
      setUser={setUser}
      deepScan={deepScan}
      setDeepScan={setDeepScan}
      NAV_ITEMS={NAV_ITEMS}
      TMGC_VERSION={TMGC_VERSION}
      emailText={emailText}
      setEmailText={setEmailText}
      emailResult={emailResult}
      loadingEmail={loadingEmail}
      analyzeEmailPhishing={analyzeEmailPhishing}
      cnnResult={cnnResult}
      loadingCNN={loadingCNN}
      analyzeCNN={analyzeCNN}
      gnnResult={gnnResult}
      loadingGNN={loadingGNN}
      analyzeGNN={analyzeGNN}
      ensembleResult={ensembleResult}
      loadingEnsemble={loadingEnsemble}
      analyzeEnsemble={analyzeEnsemble}
      mlInferenceMs={mlInferenceMs}
    />
  );
}


function AuthScreen({ onAuthenticated }) {
  const [mode, setMode] = useState("login");
  const [form, setForm] = useState({ name: "", email: "", password: "", confirm: "" });
  const [error, setError] = useState("");

  function update(key, value) {
    setForm((current) => ({ ...current, [key]: value }));
  }

  async function hashPassword(password, salt) {
    const encoder = new TextEncoder();
    const data = encoder.encode(password + salt);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
  }

  function generateSalt() {
    const array = new Uint8Array(16);
    crypto.getRandomValues(array);
    return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
  }

  function generateSessionToken() {
    const array = new Uint8Array(32);
    crypto.getRandomValues(array);
    return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
  }

  async function submit(event) {
    event.preventDefault();
    setError("");
    const emailOk = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(form.email);
    if (!emailOk) return setError("Enter a valid email address.");
    if (form.password.length < 8) return setError("Password must be at least 8 characters.");
    if (mode === "signup") {
      if (form.name.trim().length < 3) return setError("Name must be at least 3 characters.");
      if (form.password !== form.confirm) return setError("Passwords do not match.");
    }

    const email = form.email.trim().toLowerCase();
    const usersKey = "tmgc_users";
    const users = JSON.parse(localStorage.getItem(usersKey) || "{}");

    if (mode === "signup") {
      if (users[email]) {
        return setError("Account already exists. Please login.");
      }
      const salt = generateSalt();
      const passwordHash = await hashPassword(form.password, salt);
      users[email] = {
        name: form.name.trim() || "Analyst",
        email,
        passwordHash,
        salt,
        createdAt: Date.now(),
      };
      localStorage.setItem(usersKey, JSON.stringify(users));
    } else {
      const userRecord = users[email];
      if (!userRecord) {
        return setError("Invalid email or password.");
      }
      const passwordHash = await hashPassword(form.password, userRecord.salt);
      if (passwordHash !== userRecord.passwordHash) {
        return setError("Invalid email or password.");
      }
    }

    const sessionToken = generateSessionToken();
    const user = { name: users[email].name, email };
    localStorage.setItem("tmgc_user", JSON.stringify(user));
    localStorage.setItem("tmgc_session", sessionToken);
    onAuthenticated(user);
  }

  return (
    <main className="relative min-h-screen overflow-hidden bg-[#0a0a0a] text-zinc-300">
      <CyberStyles />
      <div className="tmgc-hero-gradient pointer-events-none absolute inset-0" />
      <div className="tmgc-grid-bg pointer-events-none absolute inset-0 opacity-40" />

      <section className="relative mx-auto flex min-h-screen max-w-7xl flex-col px-4 py-6 lg:flex-row lg:items-center lg:gap-8 lg:px-8">
        {/* Hero + 3D Globe */}
        <div className="flex flex-1 flex-col items-center lg:items-start" style={{ animation: "tmgc-fade-in 0.8s ease" }}>
          <div className="mb-6 flex items-center gap-3">
            <div className="flex h-11 w-11 items-center justify-center rounded-xl border border-[#00ff88]/40 bg-[#00ff88]/10 text-xl font-black text-[#00ff88] shadow-[0_0_30px_rgba(0,255,136,.25)]">T</div>
            <div>
              <p className="text-xl font-extrabold tracking-wide text-[#00ff88]">TMGC</p>
              <p className="text-[9px] font-semibold tracking-[0.3em] text-[#00ff88]/50 uppercase">Forensic Pipeline</p>
            </div>
          </div>

          <h1 className="max-w-lg text-center text-4xl font-black leading-tight tracking-tight text-white lg:text-left lg:text-5xl">
            Detect.{" "}
            <span className="bg-gradient-to-r from-[#00ff88] to-[#00ccaa] bg-clip-text text-transparent">Investigate.</span>{" "}
            Stay Ahead.
          </h1>
          <p className="mt-4 max-w-md text-center text-sm leading-relaxed text-zinc-500 lg:text-left">
            Real-time domain threat analysis powered by machine learning, DNS forensics, and AI-driven intelligence. Scan any URL in seconds and get actionable security insights.
          </p>

          <div className="relative my-8 flex justify-center lg:justify-start">
            <CyberGlobe size={360} className="mx-auto" />
          </div>

          <div className="mb-6 flex flex-wrap justify-center gap-3 lg:justify-start">
            <button
              type="button"
              className="tmgc-btn-primary rounded-lg px-6 py-3 text-sm font-semibold"
              onClick={() => { setMode("signup"); document.getElementById("auth-form")?.scrollIntoView({ behavior: "smooth", block: "center" }); }}
            >
              Get Started →
            </button>
            <button
              type="button"
              className="rounded-lg border border-white/20 bg-transparent px-6 py-3 text-sm font-semibold text-zinc-300 transition hover:border-[#00ff88]/40 hover:text-white"
              onClick={() => document.getElementById("auth-form")?.scrollIntoView({ behavior: "smooth", block: "center" })}
            >
              Learn More
            </button>
          </div>

          <div className="grid w-full max-w-lg grid-cols-2 gap-3 sm:grid-cols-4">
            {[
              { val: "2.1M+", label: "Domains Analyzed" },
              { val: "99.2%", label: "Detection Rate" },
              { val: "<3s", label: "Avg Scan Time" },
              { val: "24/7", label: "Threat Monitoring" },
            ].map((s) => (
              <div key={s.label} className="rounded-lg border border-[#00ff88]/10 bg-black/30 px-3 py-3 text-center backdrop-blur-sm">
                <p className="text-lg font-extrabold text-[#00ff88]">{s.val}</p>
                <p className="mt-0.5 text-[9px] font-medium tracking-wide text-zinc-600 uppercase">{s.label}</p>
              </div>
            ))}
          </div>
        </div>

        {/* Auth Form */}
        <div id="auth-form" className="mt-8 w-full max-w-md shrink-0 lg:mt-0" style={{ animation: "tmgc-slide-up 0.8s ease 0.2s both" }}>
          <div className="overflow-hidden rounded-2xl border border-[#00ff88]/15 bg-[#0c0c0c]/90 shadow-[0_0_60px_rgba(0,255,136,.06)] backdrop-blur-xl">
            <form className="p-7" onSubmit={submit}>
              <p className="mb-1 text-lg font-bold text-white">{mode === "login" ? "Welcome Back" : "Create Account"}</p>
              <p className="mb-6 text-xs text-zinc-500">
                {mode === "login" ? "Sign in to access your forensic dashboard" : "Join the threat intelligence platform"}
              </p>

              <div className="mb-6 grid grid-cols-2 overflow-hidden rounded-lg border border-[#00ff88]/15">
                <button type="button" className={`px-4 py-2.5 text-sm font-semibold transition ${mode === "login" ? "bg-[#00ff88]/15 text-[#00ff88]" : "text-zinc-500 hover:text-zinc-400"}`} onClick={() => setMode("login")}>
                  Sign In
                </button>
                <button type="button" className={`px-4 py-2.5 text-sm font-semibold transition ${mode === "signup" ? "bg-[#00ff88]/15 text-[#00ff88]" : "text-zinc-500 hover:text-zinc-400"}`} onClick={() => setMode("signup")}>
                  Sign Up
                </button>
              </div>

              {mode === "signup" && (
                <AuthInput label="Full Name" value={form.name} onChange={(value) => update("name", value)} autoComplete="name" placeholder="Security Analyst" />
              )}
              <AuthInput label="Email Address" type="email" value={form.email} onChange={(value) => update("email", value)} autoComplete="email" placeholder="analyst@company.com" />
              <AuthInput label="Password" type="password" value={form.password} onChange={(value) => update("password", value)} autoComplete={mode === "login" ? "current-password" : "new-password"} placeholder="Min. 8 characters" />
              {mode === "signup" && (
                <AuthInput label="Confirm Password" type="password" value={form.confirm} onChange={(value) => update("confirm", value)} autoComplete="new-password" placeholder="Re-enter password" />
              )}

              {error && <div className="mb-4 rounded-lg border border-red-500/30 bg-red-950/20 px-4 py-3 text-sm text-red-300">{error}</div>}

              <button type="submit" className="tmgc-btn-primary w-full rounded-lg px-4 py-3.5 text-sm tracking-wide">
                {mode === "login" ? "Launch Dashboard →" : "Get Started →"}
              </button>

              <p className="mt-4 text-center text-[10px] text-zinc-600">
                Protected by end-to-end encryption · Your data stays local
              </p>
            </form>
          </div>
        </div>
      </section>
    </main>
  );
}

function AuthInput({ label, value, onChange, type = "text", autoComplete, placeholder }) {
  return (
    <label className="mb-4 block">
      <span className="mb-1.5 block text-xs font-semibold text-zinc-400">{label}</span>
      <input
        className="w-full rounded-lg border border-[#00ff88]/12 bg-black/50 px-4 py-3 text-sm text-zinc-200 outline-none transition placeholder:text-zinc-700 focus:border-[#00ff88]/40 focus:shadow-[0_0_20px_rgba(0,255,136,.08)]"
        type={type}
        value={value}
        onChange={(event) => onChange(event.target.value)}
        autoComplete={autoComplete}
        placeholder={placeholder}
      />
    </label>
  );
}

function normalizeResult(result) {
  if (!result) return null;
  const parsedMeta = {
    hosting_space: nvl(result.parsed_meta?.hosting_space ?? result.hosting_space),
    domain_age: nvl(result.parsed_meta?.domain_age ?? result.domain_age),
    created_date: nvl(result.parsed_meta?.created_date),
    updated_date: nvl(result.parsed_meta?.updated_date),
    expiry_date: nvl(result.parsed_meta?.expiry_date),
    asn: nvl(result.parsed_meta?.asn ?? result.asn),
    country: nvl(result.parsed_meta?.country ?? result.country_code),
    http_status: nvl(result.parsed_meta?.http_status ?? result.final_http_status),
    ssl_issuer: nvl(result.parsed_meta?.ssl_issuer ?? result.ssl_issuer),
    registrar: nvl(result.parsed_meta?.registrar ?? result.registrar),
  };
  const rawLogs = result.raw_logs || rawLogsFromCommands(result.commands || {});
  const details = Array.isArray(result.security_header_details)
    ? result.security_header_details
    : Array.isArray(result.security_headers)
      ? result.security_headers
      : Object.entries(result.security_headers || {}).map(([name, enabled]) => ({ name, enabled: Boolean(enabled) }));
  const headerDetails = (details.length ? details : defaultHeaderRows()).map(normalizeHeaderRow);
  const whoisRaw = rawLogs.domain_whois || "";
  return {
    original: result,
    domain: result.domain || "target",
    ip_address: result.ip_address || result.target_ip || "",
    parsed_meta: parsedMeta,
    security_header_details: headerDetails,
    score_components: result.score_components || {},
    ml_result: result.ml_result || {},
    raw_logs: rawLogs,
    raw_context: result.raw_context || "",
    findings: result.findings || [],
    ai_verdict: result.ai_verdict || result.ai_markdown_report || "",
    risk_score: Number(result.risk_score || 0),
    ssl_dates: result.ssl_dates || {},
    nameservers: result.dns_data?.nameservers || [],
    dnssec: /dnssec.*signed/i.test(whoisRaw) ? "Enabled" : whoisRaw ? "Unknown" : "N/A",
    ssl_protocol: extractSslProtocol(rawLogs),
    ensemble_ml: result.ensemble_ml || null,
    owner_image: result.owner_image || null,
  };
}

function extractSslProtocol(rawLogs) {
  const ssl = rawLogs?.ssl || "";
  const match = ssl.match(/TLSv[\d.]+|Protocol\s*:\s*(TLS[^\s,]+)/i);
  return match ? match[0].replace(/^Protocol\s*:\s*/i, "") : "N/A";
}

function rawLogsFromCommands(commands) {
  const map = {};
  RAW_TABS.forEach((key) => {
    const command = commands[key] || {};
    map[key] = command.stdout || command.stderr || command.error || "";
  });
  return map;
}

function defaultHeaderRows() {
  return [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "Content-Security-Policy-Report-Only",
    "X-Frame-Options",
    "X-XSS-Protection",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
    "Cross-Origin-Embedder-Policy",
    "Cross-Origin-Opener-Policy",
    "Cross-Origin-Resource-Policy",
  ].map((name) => normalizeHeaderRow({ name, enabled: false }));
}

function buildCnnDomFeatures(data) {
  const components = data?.score_components || {};
  const rawLogs = data?.raw_logs || {};
  const htmlLike = [rawLogs.curl, rawLogs.browser, rawLogs.content].filter(Boolean).join("\n");
  const findingsText = (data?.findings || []).join(" ");
  const headerMissing = (data?.security_header_details || []).filter((header) => !header.enabled).length;
  return {
    total_elements: countMatches(htmlLike, /<[a-zA-Z][^>\s]*/g) || Number(components.total_elements || 0),
    form_count: countMatches(htmlLike, /<form\b/gi) || Number(components.form_count || 0),
    password_form_count: countMatches(htmlLike, /type\s*=\s*["']?password/gi) || Number(components.password_form_count || 0),
    script_count: countMatches(htmlLike, /<script\b/gi) || Number(components.script_count || 0),
    image_count: countMatches(htmlLike, /<img\b/gi) || Number(components.image_count || 0),
    iframe_count: countMatches(htmlLike, /<iframe\b/gi) || Number(components.iframe_count || 0),
    hidden_element_count: countMatches(htmlLike, /display\s*:\s*none|visibility\s*:\s*hidden/gi) || Number(components.hidden_element_count || 0),
    external_script_count: countMatches(htmlLike, /<script[^>]+src\s*=\s*["']https?:\/\//gi) || Number(components.external_script_count || 0),
    brands_detected_count: countMatches(findingsText, /brand|impersonat|typosquat|homograph/gi) || Number(components.brands_detected_count || 0),
    obfuscation_count: countMatches(htmlLike, /eval\s*\(|document\.write\s*\(|\\x[0-9a-f]{2}/gi) || Number(components.obfuscation_count || 0),
    html_length: htmlLike.length || Number(components.html_length || components.content_length || 0),
    has_login_form: /login|password|credential/i.test(htmlLike + findingsText),
    has_external_action: countMatches(htmlLike, /<form[^>]+action\s*=\s*["']https?:\/\//gi) > 0,
    missing_security_headers: headerMissing,
  };
}

function buildVisualFeatures(data) {
  const components = data?.score_components || {};
  return {
    width: Number(components.viewport_width || 0),
    height: Number(components.viewport_height || 0),
    aspect_ratio: Number(components.aspect_ratio || 0),
    dark_ratio: Number(components.dark_ratio || 0),
    light_ratio: Number(components.light_ratio || 0),
    entropy: Number(components.visual_entropy || 0),
  };
}

function buildGraphFeatures(data) {
  const nameservers = data?.nameservers || [];
  const sharedCount = Number(data?.score_components?.shared_infrastructure_count || 0);
  const nodeCount = Math.max(1, 1 + nameservers.length + (data?.ip_address ? 1 : 0));
  const edgeCount = Math.max(sharedCount, nameservers.length + (data?.ip_address ? 1 : 0));
  const maxEdges = nodeCount * (nodeCount - 1) / 2;
  return {
    node_count: Number(data?.score_components?.node_count || nodeCount),
    edge_count: Number(data?.score_components?.edge_count || edgeCount),
    density: Number(data?.score_components?.density || (maxEdges ? edgeCount / maxEdges : 0)),
    avg_degree: Number(data?.score_components?.avg_degree || (nodeCount ? (2 * edgeCount) / nodeCount : 0)),
    max_degree: Number(data?.score_components?.max_degree || Math.max(1, nameservers.length)),
    cluster_count: Number(data?.score_components?.cluster_count || 0),
    largest_cluster_size: Number(data?.score_components?.largest_cluster_size || 0),
    shared_infrastructure_count: sharedCount,
    centrality_max: Number(data?.score_components?.centrality_max || (nodeCount > 1 ? Math.max(1, nameservers.length) / (nodeCount - 1) : 0)),
    centrality_avg: Number(data?.score_components?.centrality_avg || 0),
    nameserver_count: nameservers.length,
    has_ip: Boolean(data?.ip_address),
  };
}

function countMatches(text, regex) {
  return String(text || "").match(regex)?.length || 0;
}

function normalizeHeaderRow(header) {
  const enabled = Boolean(header.enabled || header.effective);
  const status = header.status || header.strength || (enabled ? "STRONG" : "MISSING");
  return {
    name: header.name,
    enabled,
    effective: header.effective ?? enabled,
    value: header.value || "",
    status,
    strength: header.strength || status,
    evidence: header.evidence || "",
    recommendation: header.recommendation || "",
    redirect_index: header.redirect_index ?? null,
    source_url: header.source_url || "",
  };
}

function nvl(value) {
  if (value === null || value === undefined || value === "" || value === "UNKNOWN") return "N/A";
  return value;
}

function downloadBlob(filename, content, type) {
  const blob = new Blob([content], { type });
  const link = document.createElement("a");
  link.href = URL.createObjectURL(blob);
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(link.href);
}

function drawHighlightedPdfLine(doc, text, x, y) {
  const upper = String(text).toUpperCase();
  const hasKeyword = KEYWORDS.some((keyword) => upper.includes(keyword));
  doc.setFont("courier", hasKeyword ? "bold" : "normal");
  doc.setTextColor(hasKeyword ? 190 : 0, hasKeyword ? 45 : 180, hasKeyword ? 45 : 70);
  doc.text(String(text), x, y);
}

function escapeRegex(text) {
  return text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

export default App;
