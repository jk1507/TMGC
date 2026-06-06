import React, { useMemo, useState } from "react";

const API_URL = import.meta.env.VITE_API_URL || "http://127.0.0.1:8000/api/v1/analyze";
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
  const [logs, setLogs] = useState(["RETRO_INTEL SHELL READY.", "AWAITING TARGET INPUT..."]);
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [activeTab, setActiveTab] = useState("dig");

  const data = useMemo(() => normalizeResult(result), [result]);
  const highRisk = (data?.risk_score || 0) > 60;
  const accent = highRisk ? "border-red-500 text-red-400 shadow-[0_0_24px_rgba(239,68,68,0.45)]" : "border-green-500 text-green-400 shadow-[0_0_24px_rgba(34,197,94,0.35)]";
  const headerRows = useMemo(() => data?.security_header_details || defaultHeaderRows(), [data]);

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

  function exportJson() {
    if (!data) return;
    downloadBlob(`threat_matrix_${data.domain}.json`, JSON.stringify(data.original, null, 2), "application/json;charset=utf-8");
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
      .map((header) => `- ${header.enabled ? "[ENABLED]" : "[MISSING]"} ${header.name}${header.value ? `: ${header.value}` : ""}`)
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
      headerRows.forEach((header) => line(`${header.name}: ${header.enabled ? "ENABLED" : "MISSING"}${header.value ? ` | ${header.value}` : ""}`));

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
      `}</style>

      <div className="crt absolute inset-0 animate-[crt-flicker_2.4s_infinite]" />
      <section className={`relative z-10 mx-auto grid max-w-7xl gap-4 rounded border bg-black/90 p-4 ${accent} lg:grid-cols-[1.1fr_.9fr]`}>
        <header className="col-span-full border-b border-green-700 pb-3">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div>
              <p className="text-xs tracking-[0.35em] text-green-300">RETRO_INTEL // OSINT DOMAIN THREAT ANALYZER</p>
              <h1 className="text-2xl font-black text-green-400 shadow-[0_0_10px_rgba(0,255,0,0.5)]">ROOT@SOC:~$ FORENSIC_PIPELINE</h1>
            </div>
            <div className={`border px-3 py-2 ${highRisk ? "animate-pulse border-red-500 text-red-400" : "border-green-600 text-green-300"}`}>
              SCORE::{data ? data.risk_score.toString().padStart(3, "0") : "---"}
            </div>
          </div>
        </header>

        <section className="min-h-[620px] rounded border border-green-800 bg-black p-4 shadow-[inset_0_0_28px_rgba(0,255,0,0.08)]">
          <label className="block text-sm text-green-300">TARGET WEBSITE</label>
          <div className="mt-2 flex gap-2">
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
          <h2 className="border-b border-green-800 pb-2 text-lg font-bold">DATA MATRIX</h2>
          <div className="mt-4 grid gap-3 text-sm">
            <Matrix label="TARGET IP" value={data?.ip_address || "N/A"} />
            <Matrix label="HOSTING SPACE" value={data?.parsed_meta.hosting_space || "N/A"} />
            <Matrix label="DOMAIN AGE" value={data?.parsed_meta.domain_age || "N/A"} />
            <Matrix label="ASN / COUNTRY" value={`${data?.parsed_meta.asn || "N/A"} / ${data?.parsed_meta.country || "N/A"}`} />
            <Matrix label="HTTP STATUS" value={data?.parsed_meta.http_status || "N/A"} />
            <Matrix label="SSL ISSUER" value={data?.parsed_meta.ssl_issuer || "N/A"} />
          </div>

          <h3 className="mt-5 border-b border-green-800 pb-2 font-bold">SECURITY HEADERS</h3>
          <div className="mt-3 grid gap-2 text-sm">
            {headerRows.map((header) => (
              <div key={header.name} className="flex items-center justify-between gap-3 border border-green-950 p-2">
                <span>{header.name}</span>
                <span className="flex items-center gap-2">
                  <Dot enabled={header.enabled} />
                  {header.enabled ? "ENABLED" : "MISSING"}
                </span>
              </div>
            ))}
          </div>

          <div className="mt-5 grid grid-cols-2 gap-2 text-xs">
            <ExportButton disabled={!data} onClick={exportJson} label="EXPORT_JSON" />
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

          <pre className="mt-3 max-h-48 overflow-y-auto whitespace-pre-wrap border border-green-900 p-3 text-xs text-green-300">
            {data?.raw_logs[activeTab] || "RAW TERMINAL EVIDENCE WILL MATERIALIZE HERE AFTER PIPELINE COMPLETION."}
          </pre>

          <div className="mt-4 max-h-64 overflow-y-auto whitespace-pre-wrap border border-green-900 p-3 text-xs text-green-300">
            {data ? <HighlightedText text={data.ai_verdict} /> : "AI EVALUATION LOG WILL MATERIALIZE HERE AFTER PIPELINE COMPLETION."}
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
  return {
    original: result,
    domain: result.domain || "target",
    ip_address: result.ip_address || result.target_ip || "",
    parsed_meta: parsedMeta,
    security_header_details: details.length ? details : defaultHeaderRows(),
    raw_logs: rawLogs,
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
  return ["Strict-Transport-Security", "Content-Security-Policy", "X-Frame-Options", "X-XSS-Protection"].map((name) => ({ name, enabled: false }));
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
