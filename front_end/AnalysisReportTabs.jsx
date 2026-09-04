import React, { useState } from "react";
import { Dot, HeaderBadge, HighlightedText } from "./dashboardShared.jsx";
import NetworkGraph from "./NetworkGraph.jsx";

const TABS = [
  { id: "overview", label: "Overview" },
  { id: "threat-intel", label: "Threat Intelligence" },
  { id: "ssl", label: "SSL/TLS" },
  { id: "dns", label: "DNS Records" },
  { id: "content", label: "Content Analysis" },
  { id: "reputation", label: "Reputation" },
  { id: "ai", label: "AI Analysis" },
  { id: "graph", label: "Graph View" },
];

function ThreatBar({ label, score, color }) {
  const level = score >= 60 ? "High" : score >= 30 ? "Medium" : "Low";
  return (
    <div className="space-y-1.5">
      <div className="flex items-center justify-between text-xs">
        <span className="text-zinc-400">{label}</span>
        <span className="font-bold text-zinc-300">{score}/100 · {level}</span>
      </div>
      <div className="h-2 overflow-hidden rounded-full bg-black/50">
        <div
          className="h-full rounded-full transition-all duration-700"
          style={{ width: `${Math.min(100, score)}%`, backgroundColor: color, boxShadow: `0 0 8px ${color}66` }}
        />
      </div>
    </div>
  );
}

function RiskGauge({ score, label, labelColor }) {
  const pct = Math.max(0, Math.min(100, score));
  const circumference = 2 * Math.PI * 48;
  const offset = circumference - (pct / 100) * circumference;
  const stroke = score >= 71 ? "#ef4444" : score >= 46 ? "#f87171" : score >= 26 ? "#facc15" : "#00ff88";

  return (
    <div className="flex flex-col items-center">
      <div className="relative h-32 w-32">
        <svg className="h-full w-full -rotate-90" viewBox="0 0 120 120">
          <circle cx="60" cy="60" r="48" fill="none" stroke="rgba(0,255,136,.08)" strokeWidth="7" />
          <circle
            cx="60"
            cy="60"
            r="48"
            fill="none"
            stroke={stroke}
            strokeWidth="7"
            strokeLinecap="round"
            strokeDasharray={circumference}
            strokeDashoffset={offset}
            style={{ filter: `drop-shadow(0 0 10px ${stroke}88)` }}
          />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className="text-3xl font-black text-white">{score}</span>
          <span className="text-[9px] text-zinc-500">/ 100</span>
        </div>
      </div>
      <p className={`mt-2 text-sm font-bold uppercase tracking-wide ${labelColor}`}>{label}</p>
    </div>
  );
}

export default function AnalysisReportTabs({
  data,
  target,
  riskScore,
  verdictInfo,
  threatCategories,
  headerRows,
  aiReport,
  loadingAI,
  runAIAnalysis,
  activeTab,
  setActiveTab,
}) {
  const [tab, setTab] = useState("overview");
  const domain = data?.domain || target || "—";
  const sslValid = data?.parsed_meta?.ssl_issuer && data.parsed_meta.ssl_issuer !== "N/A";

  if (!data) {
    return (
      <section className="tmgc-card rounded-2xl p-8 text-center">
        <p className="text-sm text-zinc-500">Run an analysis to view the full forensic report</p>
      </section>
    );
  }

  const statusClass =
    riskScore >= 71 ? "border-red-500/40 bg-red-500/10 text-red-400" :
    riskScore >= 46 ? "border-red-500/30 bg-red-500/5 text-red-300" :
    riskScore >= 26 ? "border-yellow-500/40 bg-yellow-500/10 text-yellow-400" :
    "border-green-500/40 bg-green-500/10 text-green-400";

  return (
    <section id="analysis-report" className="tmgc-card overflow-hidden rounded-2xl">
      {/* Report header */}
      <div className="border-b border-[#00ff88]/10 px-6 py-5">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div>
            <p className="text-[10px] font-bold tracking-[0.2em] text-[#00ff88]/50 uppercase">Analysis Report</p>
            <h2 className="mt-1 text-2xl font-extrabold text-white">{domain}</h2>
            <div className="mt-3 flex flex-wrap items-center gap-3 text-xs text-zinc-500">
              <span>Domain Age: <strong className="text-zinc-300">{data.parsed_meta?.domain_age || "—"}</strong></span>
              <span className="text-zinc-700">·</span>
              <span>IP: <strong className="font-mono text-zinc-300">{data.ip_address || "—"}</strong></span>
              {data.parsed_meta?.country && data.parsed_meta.country !== "N/A" && (
                <>
                  <span className="text-zinc-700">·</span>
                  <span>{data.parsed_meta.country}</span>
                </>
              )}
            </div>
          </div>
          <div className="flex items-center gap-4">
            <div className={`rounded-xl border px-4 py-3 text-center ${statusClass}`}>
              <p className="text-[10px] font-bold tracking-wider uppercase opacity-80">{verdictInfo.title}</p>
              <p className="text-2xl font-black">{riskScore}/100</p>
            </div>
            <RiskGauge score={riskScore} label={verdictInfo.title} labelColor={verdictInfo.titleColor} />
          </div>
        </div>

        {/* Tabs */}
        <div className="tmgc-scrollbar mt-5 flex gap-1 overflow-x-auto border-b border-[#00ff88]/8 pb-px">
          {TABS.map((t) => (
            <button
              key={t.id}
              type="button"
              onClick={() => setTab(t.id)}
              className={`shrink-0 rounded-t-lg px-4 py-2.5 text-xs font-semibold transition ${
                tab === t.id
                  ? "border-b-2 border-[#00ff88] bg-[#00ff88]/8 text-[#00ff88]"
                  : "text-zinc-500 hover:text-zinc-300"
              }`}
            >
              {t.label}
            </button>
          ))}
        </div>
      </div>

      <div className="p-6">
        {tab === "overview" && (
          <div className="grid gap-6 lg:grid-cols-2">
            <div>
              <h3 className="tmgc-section-title-plain mb-4">Domain Information</h3>
              <div className="overflow-hidden rounded-xl border border-[#00ff88]/8">
                {[
                  ["Registrar", data.parsed_meta?.registrar],
                  ["Registration Date", data.parsed_meta?.created_date],
                  ["Expiry Date", data.parsed_meta?.expiry_date],
                  ["Nameservers", data.nameservers?.length ? data.nameservers.join(", ") : "—"],
                  ["DNSSEC", data.dnssec],
                  ["HTTP Status", data.parsed_meta?.http_status],
                ].map(([label, value]) => (
                  <div key={label} className="flex justify-between gap-4 border-b border-[#00ff88]/5 px-4 py-3 text-sm last:border-0">
                    <span className="text-zinc-500">{label}</span>
                    <span className="max-w-[55%] truncate text-right font-medium text-zinc-300">{value || "—"}</span>
                  </div>
                ))}
              </div>
            </div>
            <div>
              <h3 className="tmgc-section-title-plain mb-4">Threat Score Breakdown</h3>
              <div className="space-y-4">
                {threatCategories.map((cat) => (
                  <ThreatBar key={cat.name} label={cat.name} score={cat.score} color={cat.color} />
                ))}
              </div>
            </div>
          </div>
        )}

        {tab === "threat-intel" && (
          <div className="space-y-4">
            <h3 className="tmgc-section-title-plain">Threat Intelligence</h3>
            {data.findings?.length ? (
              <div className="space-y-2">
                {data.findings.map((finding, i) => (
                  <div key={i} className="rounded-lg border border-[#00ff88]/8 bg-black/30 px-4 py-3 text-sm text-zinc-400">
                    <HighlightedText text={finding} />
                  </div>
                ))}
              </div>
            ) : (
              <p className="text-sm text-zinc-500">No threat intelligence findings recorded.</p>
            )}
          </div>
        )}

        {tab === "ssl" && (
          <div className="grid gap-4 sm:grid-cols-2">
            {[
              ["Issuer", data.parsed_meta?.ssl_issuer],
              ["Valid From", data.ssl_dates?.not_before],
              ["Valid To", data.ssl_dates?.not_after],
              ["Protocol", data.ssl_protocol],
              ["Status", sslValid ? "Valid Certificate" : "Issues Detected"],
            ].map(([label, value]) => (
              <div key={label} className="rounded-xl border border-[#00ff88]/8 bg-black/30 p-4">
                <p className="text-[10px] font-bold text-zinc-500 uppercase">{label}</p>
                <p className={`mt-1 text-sm font-semibold ${label === "Status" && !sslValid ? "text-red-400" : "text-zinc-200"}`}>{value || "—"}</p>
              </div>
            ))}
          </div>
        )}

        {tab === "dns" && (
          <div className="space-y-4">
            <div className="grid gap-3 sm:grid-cols-2">
              <div className="rounded-xl border border-[#00ff88]/8 bg-black/30 p-4">
                <p className="text-[10px] font-bold text-zinc-500 uppercase">Nameservers</p>
                <ul className="mt-2 space-y-1">
                  {(data.nameservers?.length ? data.nameservers : ["—"]).map((ns) => (
                    <li key={ns} className="font-mono text-xs text-zinc-300">{ns}</li>
                  ))}
                </ul>
              </div>
              <div className="rounded-xl border border-[#00ff88]/8 bg-black/30 p-4">
                <p className="text-[10px] font-bold text-zinc-500 uppercase">DNSSEC</p>
                <p className="mt-2 text-sm text-zinc-300">{data.dnssec || "—"}</p>
              </div>
            </div>
            {data.raw_logs?.dig && (
              <div className="rounded-xl border border-[#00ff88]/8 bg-black/40 p-4">
                <p className="mb-2 text-[10px] font-bold text-zinc-500 uppercase">Raw DNS (dig)</p>
                <pre className="tmgc-mono max-h-40 overflow-auto whitespace-pre-wrap text-xs text-[#00ff88]/70">{data.raw_logs.dig.slice(0, 3000)}</pre>
              </div>
            )}
          </div>
        )}

        {tab === "content" && (
          <div>
            {data.raw_logs?.curl ? (
              <pre className="tmgc-mono tmgc-scrollbar max-h-80 overflow-auto whitespace-pre-wrap rounded-xl border border-[#00ff88]/8 bg-black/40 p-4 text-xs text-[#00ff88]/70">
                {data.raw_logs.curl.slice(0, 8000)}
              </pre>
            ) : (
              <p className="text-sm text-zinc-500">No content analysis data available.</p>
            )}
          </div>
        )}

        {tab === "reputation" && (
          <div className="space-y-3">
            <div className="rounded-xl border border-[#00ff88]/8 bg-black/30 p-4">
              <p className="text-[10px] font-bold text-zinc-500 uppercase">Overall Verdict</p>
              <p className={`mt-1 text-lg font-bold ${verdictInfo.titleColor}`}>{verdictInfo.title}</p>
              <p className="mt-1 text-sm text-zinc-500">{verdictInfo.subtitle}</p>
            </div>
            {data.ml_result?.xgb_available && (
              <div className="rounded-xl border border-purple-500/20 bg-purple-950/10 p-4">
                <p className="text-[10px] font-bold text-purple-400 uppercase">ML Verdict</p>
                <p className="mt-1 text-sm text-zinc-300">{data.ml_result.xgb_verdict?.toUpperCase()} — Score: {data.ml_result.xgb_score}/100</p>
              </div>
            )}
          </div>
        )}

        {tab === "ai" && (
          <div>
            <div className="mb-4 flex justify-end">
              <button
                type="button"
                className="rounded-lg border border-cyan-500/40 bg-cyan-500/10 px-4 py-2 text-xs font-bold text-cyan-300 disabled:opacity-40"
                disabled={loadingAI}
                onClick={() => runAIAnalysis?.(data.raw_context || "")}
              >
                {loadingAI ? "Running..." : "Run AI Analysis"}
              </button>
            </div>
            {loadingAI ? (
              <p className="text-sm text-cyan-400">Running AI threat reasoning...</p>
            ) : aiReport ? (
              <div className="tmgc-scrollbar max-h-96 overflow-y-auto whitespace-pre-wrap text-sm leading-relaxed text-cyan-100/80">
                <HighlightedText text={aiReport.formatted_report || aiReport.analysis || JSON.stringify(aiReport, null, 2)} />
              </div>
            ) : (
              <p className="text-sm text-zinc-500">{data.ai_verdict || "Click Run AI Analysis for deep contextual reasoning."}</p>
            )}
          </div>
        )}

        {tab === "graph" && (
          <NetworkGraph domain={domain} data={data} className="min-h-[320px]" />
        )}
      </div>
    </section>
  );
}
