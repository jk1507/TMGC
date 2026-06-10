import React, { useMemo, useState } from "react";

const API_URL = import.meta.env.VITE_API_URL || "http://127.0.0.1:8000/api/v1/analyze";
const AI_ANALYSIS_API =
  import.meta.env.VITE_AI_ANALYSIS_API ||
  "http://127.0.0.1:8000/api/v1/ai-analysis";
const RAW_TABS = ["dig", "mx", "ip_whois", "domain_whois", "ssl", "curl", "nc"];
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

function Dot({ enabled }) {
  return (
    <span
      className={`inline-block h-2.5 w-2.5 rounded-full ${
        enabled ? "bg-green-400 shadow-[0_0_10px_rgba(74,222,128,0.9)]" : "animate-pulse bg-red-500 shadow-[0_0_10px_rgba(239,68,68,0.9)]"
      }`}
    />
  );
}

function App() {
  const [target, setTarget] = useState("example.com");
  const [user, setUser] = useState(() => JSON.parse(localStorage.getItem("tmgc_user") || "null"));
  const [logs, setLogs] = useState(["RETRO_INTEL SHELL READY.", "AWAITING TARGET INPUT..."]);
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [activeTab, setActiveTab] = useState("dig");
  const [aiReport, setAiReport] = useState(null);
  const [loadingAI, setLoadingAI] = useState(false);

  const data = useMemo(() => normalizeResult(result), [result]);
  const highRisk = (data?.risk_score || 0) >= 60;
  const verdict =
  (data?.risk_score || 0) >= 90
    ? "☠️ CRITICAL / PHISHING"
    : (data?.risk_score || 0) >= 60
    ? "🔴 HIGH RISK"
    : (data?.risk_score || 0) >= 30
    ? "🟠 SUSPICIOUS"
    : (data?.risk_score || 0) >= 30
    ? "SUSPICIOUS"
    : "SAFE / TRUSTED";
  const accent = highRisk ? "border-red-500 text-red-400 shadow-[0_0_24px_rgba(239,68,68,0.45)]" : "border-green-500 text-green-400 shadow-[0_0_24px_rgba(34,197,94,0.35)]";
 const headerRows =
  data?.security_header_details ||
  defaultHeaderRows();
  if (!user) {
    return <AuthScreen onAuthenticated={setUser} />;
  }

  async function analyze() {
    const cleanTarget = target.trim();
    if (!cleanTarget) return;

    setLoading(true);
    setError("");
    setResult(null);
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
    } catch (analysisError) {
      setError(analysisError.message || "Analysis failed.");
      setLogs((current) => [...current, `!! PIPELINE FAILURE: ${analysisError.message}`]);
    } finally {
      setLoading(false);
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
    <main className="relative min-h-screen overflow-hidden bg-black p-4 font-mono text-green-500">
      <style>{`
        @keyframes crt-flicker { 0%, 100% { opacity: .98; } 50% { opacity: .91; } }
        .crt::before {
          content: "";
          pointer-events: none;
          position: fixed;
          inset: 0;
          background: linear-gradient(rgba(18,16,16,0) 50%, rgba(0,255,0,.08) 50%), linear-gradient(90deg, rgba(255,0,0,.04), rgba(0,255,0,.02), rgba(0,0,255,.04));
          background-size: 100% 4px, 6px 100%;
          mix-blend-mode: screen;
          z-index: 50;
        }
        .intel-keyword {
          color: #f87171;
          font-weight: 900;
          text-shadow: 0 0 9px rgba(248,113,113,.75);
        }
        @media (max-width: 760px) {
          .tmgc-shell { padding: 12px; }
          .tmgc-panel { min-height: auto; }
          .tmgc-actions { display: grid; grid-template-columns: 1fr; }
          .tmgc-actions button { width: 100%; }
          .tmgc-title { font-size: 1.35rem; line-height: 1.2; }
        }
      `}</style>

      <div className="crt absolute inset-0 animate-[crt-flicker_2.4s_infinite]" />
      <section className={`tmgc-shell relative z-10 mx-auto grid max-w-7xl gap-4 rounded border bg-black/90 p-4 ${accent} lg:grid-cols-[1.1fr_.9fr]`}>
        <header className="col-span-full border-b border-green-700 pb-3">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div>
              <p className="text-xs tracking-[0.35em] text-green-300">RETRO_INTEL // OSINT DOMAIN THREAT ANALYZER</p>
              <h1 className="tmgc-title text-2xl font-black text-green-400 shadow-[0_0_10px_rgba(0,255,0,0.5)]">ROOT@SOC:~$ FORENSIC_PIPELINE</h1>
            </div>
            <div className="flex flex-wrap items-center gap-2">
              <div className="border border-cyan-700 px-3 py-2 text-xs text-cyan-300">{user.email}</div>
              <button className="border border-green-700 px-3 py-2 text-xs text-green-300 hover:bg-green-500 hover:text-black" onClick={() => { localStorage.removeItem("tmgc_user"); setUser(null); }}>
                LOGOUT
              </button>
              <div
  className={`border px-4 py-2 text-center ${
    (data?.risk_score || 0) >= 60
      ? "animate-pulse border-red-500 text-red-400"
      : (data?.risk_score || 0) >= 30
      ? "border-yellow-500 text-yellow-300"
      : "border-green-600 text-green-300"
  }`}
>
  <div className="text-xs tracking-widest">
    THREAT VERDICT
  </div>

  <div className="font-black text-sm">
    {verdict}
  </div>
<div className="text-[10px] tracking-widest text-cyan-300 mt-1">
  SOC CONFIDENCE::{
    (data?.risk_score || 0) >= 85
      ? "VERY HIGH"
      : (data?.risk_score || 0) >= 60
      ? "HIGH"
      : (data?.risk_score || 0) >= 30
      ? "MEDIUM"
      : "LOW"
  }
</div>
  <div className="mt-1 text-xs">
    SCORE::{
      data
        ? data.risk_score
            .toString()
            .padStart(3, "0")
        : "---"
    }
  </div>
</div>
            </div>
          </div>
        </header>

        <section className="tmgc-panel min-h-[620px] rounded border border-green-800 bg-black p-4 shadow-[inset_0_0_28px_rgba(0,255,0,0.08)]">
          <label className="block text-sm text-green-300">TARGET WEBSITE</label>
          <div className="tmgc-actions mt-2 flex gap-2">
            <input
              className="w-full border border-green-700 bg-black px-3 py-3 text-green-300 outline-none shadow-[0_0_10px_rgba(0,255,0,0.18)] placeholder:text-green-900"
              value={target}
              onChange={(event) => setTarget(event.target.value)}
              onKeyDown={(event) => event.key === "Enter" && analyze()}
              placeholder="https://www.gitam.edu/student/login.php"
            />
            <button
              className="border border-green-500 px-4 py-3 font-bold text-green-300 hover:bg-green-500 hover:text-black disabled:opacity-50"
              disabled={loading}
              onClick={analyze}
            >
              {loading ? "RUNNING" : "ANALYZE"}
            </button>
           <button
  className="border border-cyan-500 px-4 py-3 font-bold text-cyan-300 hover:bg-cyan-500 hover:text-black disabled:opacity-50"
  disabled={loadingAI}
  onClick={runAIAnalysis}
>
  {loadingAI ? "AI_RUNNING" : "AI_ANALYSIS"}
</button>
          </div>

          {error && <div className="mt-4 border border-red-500 p-3 text-red-400">!! {error}</div>}

          <div className="mt-4 h-[470px] overflow-y-auto border border-green-900 bg-[#001100]/40 p-4 text-sm leading-7 text-green-400">
            {logs.map((line, index) => (
              <p key={`${line}-${index}`} className="drop-shadow-[0_0_6px_rgba(34,197,94,.6)]">
                {line}
              </p>
            ))}
          </div>
        </section>

        <aside className="rounded border border-green-800 bg-black p-4">
          <h2
  className={`border-b pb-2 text-lg font-bold ${
    (data?.risk_score || 0) >= 60
      ? "border-red-700 text-red-400"
      : (data?.risk_score || 0) >= 30
      ? "border-yellow-700 text-yellow-300"
      : "border-green-800 text-green-400"
  }`}
>
  DATA MATRIX :: {verdict}
</h2>
          <div className="mt-4 grid gap-3 text-sm">
            <Matrix label="TARGET IP" value={data?.ip_address || "N/A"} />
            <Matrix label="HOSTING SPACE" value={data?.parsed_meta.hosting_space || "N/A"} />
            <Matrix label="DOMAIN AGE" value={data?.parsed_meta.domain_age || "N/A"} />
            <Matrix label="ASN / COUNTRY" value={`${data?.parsed_meta.asn || "N/A"} / ${data?.parsed_meta.country || "N/A"}`} />
            <Matrix label="HTTP STATUS" value={data?.parsed_meta.http_status || "N/A"} />
            <Matrix label="SSL ISSUER" value={data?.parsed_meta.ssl_issuer || "N/A"} />
            <div
  className={`border p-3 ${
    (data?.risk_score || 0) >= 60
      ? "border-red-900 bg-red-950/10"
      : (data?.risk_score || 0) >= 30
      ? "border-yellow-900 bg-yellow-950/10"
      : "border-green-950 bg-green-950/10"
  }`}
>
  <span className="block text-xs text-green-700">
    SCORE BREAKDOWN
  </span>

  <div className="mt-2 space-y-2 text-sm text-green-300">
    <div className="flex justify-between">
      <span>RAW EVIDENCE</span>
      <strong>
        {data?.score_components?.heuristic_analysis ?? "N/A"}
      </strong>
    </div>

    <div className="flex justify-between">
      <span>ML ENGINE</span>
      <strong>
        {data?.score_components?.xgboost_ml ?? "N/A"}
      </strong>
    </div>

    <div className="flex justify-between">
      <span>AI ANALYSIS</span>
      <strong>
        {data?.score_components?.ai_analysis ?? "UNAVAILABLE"}
      </strong>
    </div>

    <div className="flex justify-between">
      <span>SECURITY HEADERS</span>
      <strong>
        {data?.score_components?.security_headers ?? "N/A"}
      </strong>
    </div>

    <div className="border-t border-green-900 pt-2 flex justify-between font-bold text-cyan-300">
      <span>FINAL SCORE</span>
      <span>
        {data?.risk_score ?? "---"}/100
      </span>
    </div>
  </div>
</div>
          </div>
          <div
  className={`mt-5 border p-4 ${
    (data?.risk_score || 0) >= 60
      ? "border-red-800 bg-red-950/10"
      : (data?.risk_score || 0) >= 30
      ? "border-yellow-800 bg-yellow-950/10"
      : "border-green-800 bg-green-950/10"
  }`}
>
  <h3 className="font-bold mb-2">
    THREAT SUMMARY
  </h3>

  <div className="text-sm space-y-2">
    {(data?.risk_score || 0) >= 90 ? (
      <>
        <p className="text-red-400 font-bold">
          ☠️ Critical phishing likelihood.
        </p>
        <p>
          Multiple strong malicious indicators
          were detected.
        </p>
      </>
    ) : (data?.risk_score || 0) >= 60 ? (
      <>
        <p className="text-red-400 font-bold">
          High-risk infrastructure.
        </p>
        <p>
  {data?.findings?.[0] ||
    "Suspicious indicators detected."}
</p>
      </>
    ) : (data?.risk_score || 0) >= 30 ? (
      <>
        <p className="text-yellow-300 font-bold">
          Suspicious indicators found.
        </p>
        <p>
          Further manual investigation is
          recommended.
        </p>
      </>
    ) : (
      <>
        <p className="text-green-400 font-bold">
          Safe / trusted profile.
        </p>
        <p>
          No high-confidence malicious signals
          detected.
        </p>
      </>
    )}
  </div>
</div>
<div className="mt-4 border border-cyan-900 p-4 bg-cyan-950/10">
  <h3 className="mb-2 font-bold text-cyan-400">
    RISK CONTRIBUTORS
  </h3>

  <div className="space-y-2 text-sm text-cyan-200">
    {data?.findings?.length ? (
      data.findings
        .slice(0, 6)
        .map((finding, index) => (
          <div
            key={index}
            className="border-b border-cyan-950 pb-2"
          >
            {(
  finding.includes("TYPOSQUATTING") ||
  finding.includes("PHISHING") ||
  finding.includes("MALWARE") ||
  finding.includes("HIGH RISK")
) ? (
  <span className="text-red-400">
    + HIGH IMPACT
  </span>
) : (
  finding.includes("SSL") ||
  finding.includes("DEAD HOST") ||
  finding.includes("EXPOSED PORT") ||
  finding.includes("MEDIUM RISK")
) ? (
  <span className="text-yellow-300">
    + MEDIUM IMPACT
  </span>
) : (
  <span className="text-green-400">
    + LOW IMPACT
  </span>
)}
            <p className="mt-1 text-xs">
              {finding}
            </p>
          </div>
        ))
    ) : (
      <p>No significant contributors.</p>
    )}
  </div>
</div>
          <h3 className="mt-5 border-b border-green-800 pb-2 font-bold">SECURITY HEADERS</h3>
          <div className="mt-3 grid gap-2 text-sm">
            {headerRows.map((header) => (
              <div key={header.name} className="flex items-center justify-between gap-3 border border-green-950 p-2">
                <span>{header.name}</span>
                <span className="flex items-center gap-2 font-bold">
                  <Dot enabled={header.effective ?? header.enabled} />
                  <HeaderBadge header={header} />
                </span>
              </div>
            ))}
          </div>

          <div className="mt-5 grid grid-cols-2 gap-2 text-xs">
            <ExportButton disabled={!data} onClick={exportExcel} label="EXPORT_EXCEL_REPORT" />
            <ExportButton disabled={!data} onClick={exportPdf} label="DOWNLOAD_PDF_DOSSIER" />
            <ExportButton disabled={!data} onClick={exportRawTxt} label="RAW_TXT_LOG" />
            <ExportButton disabled={!data} onClick={exportMarkdown} label="EXPORT_MD_LOG" />
          </div>

          <div className="mt-4 flex flex-wrap gap-2">
            {RAW_TABS.map((tab) => (
              <button
                key={tab}
                className={`border px-2 py-1 text-xs ${activeTab === tab ? "border-green-400 bg-green-500 text-black" : "border-green-900 text-green-400 hover:border-green-500"}`}
                onClick={() => setActiveTab(tab)}
              >
                {tab}
              </button>
            ))}
          </div>
            <div className="mt-4 border border-green-900 p-4 min-h-[180px] bg-[#001100]/30">
  <h3 className="mb-2 font-bold text-green-400">
    RAW COMMAND OUTPUT :: {activeTab.toUpperCase()}
  </h3>

  <pre className="whitespace-pre-wrap text-xs text-green-300 overflow-auto max-h-[250px]">
    {
  data?.raw_logs?.[activeTab]
    ? data.raw_logs[activeTab].slice(
        0,
        15000
      )
    : "NO DATA AVAILABLE"
}
  </pre>
</div>
<div className="mt-4 border border-yellow-900 p-4 min-h-[180px] bg-[#1a1a00]/30">
  <h3 className="mb-2 font-bold text-yellow-400">
    ML THREAT ANALYSIS
  </h3>

  {data?.ml_result?.xgb_available ? (
    <div className="text-sm text-yellow-200 space-y-2">
      <p>
        <strong>MODEL:</strong> XGBoost
      </p>

      <p>
        <strong>VERDICT:</strong>{" "}
        {data.ml_result.xgb_verdict?.toUpperCase()}
      </p>

      <p>
        <strong>ML SCORE:</strong>{" "}
        {data.ml_result.xgb_score}/100
      </p>

      <p>
        <strong>WHY THIS RESULT:</strong>
      </p>

      <ul className="list-disc ml-5 text-xs space-y-1">
        {data.findings
          ?.filter((x) => x.includes("ML ANALYSIS"))
          .map((item, i) => (
            <li key={i}>{item}</li>
          ))}
      </ul>
    </div>
  ) : (
    <p className="text-yellow-300">
      ML MODEL UNAVAILABLE
    </p>
  )}
</div>
    <div className="mt-4 border border-cyan-900 p-4 min-h-[180px]">
  <h3 className="mb-2 font-bold text-cyan-400">
    AI CYBER ANALYSIS
  </h3>

  {loadingAI ? (
    <p>RUNNING AI THREAT REASONING...</p>
  ) : aiReport ? (
    <div className="text-sm text-cyan-200 whitespace-pre-wrap">
      <HighlightedText
        text={
  aiReport.formatted_report ||
  aiReport.analysis ||
  aiReport.report ||
  JSON.stringify(aiReport, null, 2)
}
      />
    </div>
  ) : (
    <div className="text-sm text-cyan-300 space-y-2">
  <p>
    Click AI_ANALYSIS to perform deep
    contextual cyber reasoning.
  </p>

  <p className="text-xs text-yellow-400">
    ML engine and heuristic scoring are
    still active even if AI analysis is
    unavailable.
  </p>
</div>
  )}
</div>
        </aside>
      </section>
    </main>
  );
}

function Matrix({ label, value }) {
  return (
    <div className="border border-green-950 p-3">
      <span className="block text-xs text-green-700">{label}</span>
      <strong className="break-words text-green-300">{value || "N/A"}</strong>
    </div>
  );
}

function HeaderBadge({ header }) {
  const status = header.status || header.strength || (header.enabled ? "STRONG" : "MISSING");
  const colors = {
    STRONG: "text-green-400",
    WEAK: "text-yellow-300",
    MISCONFIGURED: "text-red-400",
    REPORT_ONLY: "text-yellow-300",
    DEPRECATED: "text-gray-300",
    OPTIONAL: "text-cyan-300",
    MISSING: "text-red-400",
  };
  return <span className={colors[status] || "text-green-300"}>{status.replace("_", " ")}</span>;
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
    <main className="min-h-screen bg-[#070b10] px-4 py-8 font-mono text-cyan-100">
      <section className="mx-auto flex min-h-[calc(100vh-4rem)] max-w-5xl items-center justify-center">
        <div className="grid w-full overflow-hidden rounded border border-cyan-900 bg-[#0b1118] shadow-[0_0_40px_rgba(0,217,255,0.12)] md:grid-cols-[0.9fr_1.1fr]">
          <div className="border-b border-cyan-900 bg-[#091018] p-6 md:border-b-0 md:border-r">
            <p className="text-xs tracking-[0.35em] text-cyan-400">TMGC ACCESS</p>
            <h1 className="mt-3 text-3xl font-black text-white">Threat Intelligence Console</h1>
            <p className="mt-4 text-sm leading-7 text-cyan-200/70">
              Sign in to run domain checks with security headers, XGBoost ML, and AI-assisted analysis in one score.
            </p>
            <div className="mt-8 grid gap-3 text-xs text-cyan-200/80">
              <div className="border border-cyan-950 p-3">HYBRID_SCORE = HEADERS + ML + AI + RULES</div>
              <div className="border border-cyan-950 p-3">PHISHING OR SUSPICIOUS = HIGH RISK FLOOR</div>
              <div className="border border-cyan-950 p-3">RESPONSIVE SOC DASHBOARD</div>
            </div>
          </div>

          <form className="p-6" onSubmit={submit}>
            <div className="mb-6 grid grid-cols-2 border border-cyan-900">
              <button type="button" className={`px-4 py-3 text-sm ${mode === "login" ? "bg-cyan-400 text-black" : "text-cyan-300"}`} onClick={() => setMode("login")}>
                LOGIN
              </button>
              <button type="button" className={`px-4 py-3 text-sm ${mode === "signup" ? "bg-cyan-400 text-black" : "text-cyan-300"}`} onClick={() => setMode("signup")}>
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

            {error && <div className="mb-4 border border-red-500 bg-red-950/30 p-3 text-sm text-red-300">{error}</div>}
            <button className="w-full border border-cyan-400 bg-cyan-400 px-4 py-3 font-black text-black hover:bg-cyan-300">
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
      <span className="mb-2 block text-xs tracking-[0.25em] text-cyan-500">{label}</span>
      <input
        className="w-full border border-cyan-900 bg-black px-3 py-3 text-cyan-100 outline-none focus:border-cyan-400"
        type={type}
        value={value}
        onChange={(event) => onChange(event.target.value)}
        autoComplete={autoComplete}
      />
    </label>
  );
}

function ExportButton({ disabled, onClick, label }) {
  return (
    <button
      className="border border-green-500 px-2 py-3 font-black text-green-300 hover:bg-green-500 hover:text-black disabled:opacity-40"
      disabled={disabled}
      onClick={onClick}
    >
      {label}
    </button>
  );
}

function HighlightedText({ text }) {
  const regex = new RegExp(`(${KEYWORDS.map(escapeRegex).join("|")})`, "gi");
  return String(text || "").split(regex).map((part, index) => {
    const isKeyword = KEYWORDS.some((keyword) => keyword.toLowerCase() === part.toLowerCase());
    return isKeyword ? (
      <span key={`${part}-${index}`} className="intel-keyword">
        {part}
      </span>
    ) : (
      <React.Fragment key={`${part}-${index}`}>{part}</React.Fragment>
    );
  });
}

function normalizeResult(result) {
  if (!result) return null;
  const parsedMeta = {
    hosting_space: nvl(result.parsed_meta?.hosting_space ?? result.hosting_space),
    domain_age: nvl(result.parsed_meta?.domain_age ?? result.domain_age),
    created_date: nvl(result.parsed_meta?.created_date),
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
  };
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
