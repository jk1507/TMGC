import React, { useMemo, useRef, useState } from "react";
import PremiumDashboard, { getTrustScore } from "./PremiumDashboard.jsx";
import { RAW_TABS } from "./dashboardShared.jsx";

const API_URL = import.meta.env.VITE_API_URL || "http://127.0.0.1:8000/api/v1/analyze";
const AI_ANALYSIS_API =
  import.meta.env.VITE_AI_ANALYSIS_API ||
  "http://127.0.0.1:8000/api/v1/ai-analysis";
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
  { id: "reports", label: "Reports", icon: "report" },
  { id: "saved-scans", label: "Saved Scans", icon: "bookmark" },
  { id: "settings", label: "Settings", icon: "settings" },
];

const TMGC_VERSION = "v2.0.0 TMGC";

function App() {
  const [target, setTarget] = useState("example.com");
  const [user, setUser] = useState(() => JSON.parse(localStorage.getItem("tmgc_user") || "null"));
  const [logs, setLogs] = useState(["RETRO_INTEL SHELL READY.", "AWAITING TARGET INPUT..."]);
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [activeTab, setActiveTab] = useState("dig");
  const [currentView, setCurrentView] = useState("dashboard");
  const [aiReport, setAiReport] = useState(null);
  const [loadingAI, setLoadingAI] = useState(false);
  const [exportOpen, setExportOpen] = useState(false);
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [scanMeta, setScanMeta] = useState({ startedAt: null, completedAt: null, durationMs: null });
  const exportRef = useRef(null);

  const data = useMemo(() => normalizeResult(result), [result]);
  const highRisk = (data?.risk_score || 0) >= 46;
  const verdict =
  (data?.risk_score || 0) >= 71
    ? "☠️ CRITICAL / PHISHING"
    : (data?.risk_score || 0) >= 46
    ? "🔴 HIGH RISK"
    : (data?.risk_score || 0) >= 26
    ? "🟠 SUSPICIOUS"
    : (data?.risk_score || 0) >= 11
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
    setScanMeta({ startedAt, completedAt: null, durationMs: null });
    setLogs([`RETRO_INTEL SHELL > TARGET=${cleanTarget}`]);

    pipelineLogs.forEach((line, index) => {
      window.setTimeout(() => {
        setLogs((current) => [...current, line]);
      }, 180 * (index + 1));
    });

    try {
      const response = await fetch(API_URL, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: cleanTarget }),
      });

      if (!response.ok) {
        const detail = await response.json().catch(() => ({}));
        throw new Error(detail.detail || `Backend returned HTTP ${response.status}`);
      }

      const payload = await response.json();
      setResult(payload);
      setLogs((current) => [
        ...current,
        ">> AI CORE VERDICT RECEIVED.",
        `>> RISK SCORE LOCKED: ${payload.risk_score}/100`,
      ]);
      // Auto-trigger detailed AI analysis after scan completes
      setTimeout(() => {
        // Only auto-run if user hasn't manually triggered it yet
        runAIAnalysis();
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

  async function runAIAnalysis() {
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

  try {
    const response = await fetch(AI_ANALYSIS_API, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
  url: cleanTarget,
  raw_context: data?.raw_context || "",
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
      NAV_ITEMS={NAV_ITEMS}
      TMGC_VERSION={TMGC_VERSION}
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

  function submit(event) {
    event.preventDefault();
    setError("");
    const emailOk = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(form.email);
    if (!emailOk) return setError("Enter a valid email address.");
    if (form.password.length < 8) return setError("Password must be at least 8 characters.");
    if (mode === "signup") {
      if (form.name.trim().length < 3) return setError("Name must be at least 3 characters.");
      if (form.password !== form.confirm) return setError("Passwords do not match.");
    }
    const user = { name: form.name.trim() || "Analyst", email: form.email.trim().toLowerCase() };
    localStorage.setItem("tmgc_user", JSON.stringify(user));
    onAuthenticated(user);
  }

  return (
    <main className="min-h-screen bg-[#030303] px-4 py-8 text-zinc-300">
      <section className="mx-auto flex min-h-[calc(100vh-4rem)] max-w-5xl items-center justify-center">
        <div className="grid w-full overflow-hidden rounded-2xl border border-green-900/40 bg-[#050505] shadow-[0_0_60px_rgba(34,197,94,.08)] md:grid-cols-[0.9fr_1.1fr]">
          <div className="border-b border-green-900/30 bg-[#030303] p-6 md:border-b-0 md:border-r">
            <div className="flex items-center gap-2">
              <div className="flex h-10 w-10 items-center justify-center rounded-lg border border-green-500/40 bg-green-500/10 text-lg font-black text-green-400">T</div>
              <div>
                <p className="text-lg font-extrabold text-green-400">TMGC</p>
                <p className="text-[10px] font-semibold tracking-[0.2em] text-green-800">FORENSIC PIPELINE</p>
              </div>
            </div>
            <h1 className="mt-6 text-3xl font-black text-white">Threat Intelligence Console</h1>
            <p className="mt-4 text-sm leading-7 text-zinc-500">
              Sign in to run domain checks with security headers, XGBoost ML, and AI-assisted analysis in one score.
            </p>
            <div className="mt-8 grid gap-3 text-xs text-zinc-600">
              <div className="rounded-lg border border-green-950/50 bg-black/40 p-3">HYBRID_SCORE = HEADERS + ML + AI + RULES</div>
              <div className="rounded-lg border border-green-950/50 bg-black/40 p-3">PHISHING OR SUSPICIOUS = HIGH RISK FLOOR</div>
              <div className="rounded-lg border border-green-950/50 bg-black/40 p-3">PREMIUM SOC DASHBOARD</div>
            </div>
          </div>

          <form className="p-6" onSubmit={submit}>
            <p className="mb-6 text-xs font-bold tracking-[0.2em] text-green-700">SECURE ACCESS</p>
            <div className="mb-6 grid grid-cols-2 overflow-hidden rounded-lg border border-green-900/40">
              <button type="button" className={`px-4 py-3 text-sm font-semibold ${mode === "login" ? "bg-green-500/20 text-green-400" : "text-zinc-500"}`} onClick={() => setMode("login")}>
                LOGIN
              </button>
              <button type="button" className={`px-4 py-3 text-sm font-semibold ${mode === "signup" ? "bg-green-500/20 text-green-400" : "text-zinc-500"}`} onClick={() => setMode("signup")}>
                SIGNUP
              </button>
            </div>

            {mode === "signup" && (
              <AuthInput label="NAME" value={form.name} onChange={(value) => update("name", value)} autoComplete="name" />
            )}
            <AuthInput label="EMAIL" type="email" value={form.email} onChange={(value) => update("email", value)} autoComplete="email" />
            <AuthInput label="PASSWORD" type="password" value={form.password} onChange={(value) => update("password", value)} autoComplete={mode === "login" ? "current-password" : "new-password"} />
            {mode === "signup" && (
              <AuthInput label="CONFIRM PASSWORD" type="password" value={form.confirm} onChange={(value) => update("confirm", value)} autoComplete="new-password" />
            )}

            {error && <div className="mb-4 rounded-lg border border-red-500/40 bg-red-950/20 p-3 text-sm text-red-300">{error}</div>}
            <button className="w-full rounded-lg border border-green-500/60 bg-green-500/10 px-4 py-3 font-bold text-green-400 transition hover:bg-green-500/20">
              {mode === "login" ? "ENTER CONSOLE" : "CREATE ACCOUNT"}
            </button>
          </form>
        </div>
      </section>
    </main>
  );
}

function AuthInput({ label, value, onChange, type = "text", autoComplete }) {
  return (
    <label className="mb-4 block">
      <span className="mb-2 block text-xs font-bold tracking-[0.2em] text-green-800">{label}</span>
      <input
        className="w-full rounded-lg border border-green-900/50 bg-black/60 px-3 py-3 text-green-100 outline-none focus:border-green-500/50"
        type={type}
        value={value}
        onChange={(event) => onChange(event.target.value)}
        autoComplete={autoComplete}
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
