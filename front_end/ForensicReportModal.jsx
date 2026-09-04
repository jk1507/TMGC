import React, { useState } from "react";

const REPORT_TYPES = [
  { id: "executive", label: "Executive Summary", desc: "High-level overview for stakeholders" },
  { id: "technical", label: "Technical Report", desc: "Full forensic evidence and raw data" },
  { id: "ai", label: "AI Analysis Report", desc: "AI reasoning and ML model outputs" },
  { id: "custom", label: "Custom", desc: "Choose sections manually" },
];

const FORMATS = [
  { id: "pdf", label: "PDF", icon: "📄" },
  { id: "xlsx", label: "Excel", icon: "📊" },
  { id: "md", label: "Markdown", icon: "📝" },
  { id: "json", label: "JSON", icon: "{ }" },
];

const SECTIONS = [
  { id: "domain", label: "Domain Information" },
  { id: "threat", label: "Threat Score Breakdown" },
  { id: "ssl", label: "SSL/TLS Analysis" },
  { id: "dns", label: "DNS Records" },
  { id: "headers", label: "Security Headers" },
  { id: "graph", label: "Graph Analysis" },
  { id: "ai", label: "AI Model Results" },
  { id: "raw", label: "Raw Command Evidence" },
];

export default function ForensicReportModal({
  open,
  onClose,
  domain,
  exportPdf,
  exportExcel,
  exportMarkdown,
  exportJson,
}) {
  const [reportType, setReportType] = useState("executive");
  const [format, setFormat] = useState("pdf");
  const [sections, setSections] = useState(() =>
    Object.fromEntries(SECTIONS.map((s) => [s.id, true]))
  );
  const [generating, setGenerating] = useState(false);

  if (!open) return null;

  function toggleSection(id) {
    setSections((current) => ({ ...current, [id]: !current[id] }));
  }

  async function handleGenerate() {
    setGenerating(true);
    try {
      if (format === "pdf") await exportPdf?.();
      else if (format === "xlsx") await exportExcel?.();
      else if (format === "md") await exportMarkdown?.();
      else if (format === "json") await exportJson?.();
      onClose?.();
    } finally {
      setGenerating(false);
    }
  }

  return (
    <div className="fixed inset-0 z-[100] flex items-center justify-center p-4">
      <button
        type="button"
        className="absolute inset-0 bg-black/70 backdrop-blur-sm"
        onClick={onClose}
        aria-label="Close report modal"
      />
      <div
        className="relative z-10 w-full max-w-lg overflow-hidden rounded-2xl border border-[#00ff88]/20 bg-[#0c0c0c] shadow-[0_0_80px_rgba(0,255,136,.12)]"
        style={{ animation: "tmgc-slide-up 0.3s ease" }}
      >
        <div className="border-b border-[#00ff88]/10 px-6 py-5">
          <p className="text-[10px] font-bold tracking-[0.2em] text-[#00ff88]/50 uppercase">Export Forensic Data</p>
          <h2 className="mt-1 text-xl font-extrabold text-white">Generate Forensic Report</h2>
          <p className="mt-1 text-sm text-zinc-500">
            Configure and export analysis for{" "}
            <span className="font-semibold text-[#00ff88]/80">{domain || "target"}</span>
          </p>
        </div>

        <div className="tmgc-scrollbar max-h-[60vh] space-y-6 overflow-y-auto px-6 py-5">
          <div>
            <p className="mb-3 text-[10px] font-bold tracking-[0.15em] text-zinc-500 uppercase">Report Type</p>
            <div className="space-y-2">
              {REPORT_TYPES.map((type) => (
                <label
                  key={type.id}
                  className={`flex cursor-pointer items-start gap-3 rounded-xl border p-3 transition ${
                    reportType === type.id
                      ? "border-[#00ff88]/40 bg-[#00ff88]/5"
                      : "border-[#00ff88]/10 bg-black/30 hover:border-[#00ff88]/20"
                  }`}
                >
                  <input
                    type="radio"
                    name="reportType"
                    className="mt-1 accent-[#00ff88]"
                    checked={reportType === type.id}
                    onChange={() => setReportType(type.id)}
                  />
                  <div>
                    <p className="text-sm font-semibold text-zinc-200">{type.label}</p>
                    <p className="text-[11px] text-zinc-600">{type.desc}</p>
                  </div>
                </label>
              ))}
            </div>
          </div>

          <div>
            <p className="mb-3 text-[10px] font-bold tracking-[0.15em] text-zinc-500 uppercase">Output Format</p>
            <div className="grid grid-cols-4 gap-2">
              {FORMATS.map((f) => (
                <button
                  key={f.id}
                  type="button"
                  onClick={() => setFormat(f.id)}
                  className={`rounded-xl border p-3 text-center transition ${
                    format === f.id
                      ? "border-[#00ff88]/50 bg-[#00ff88]/10 shadow-[0_0_20px_rgba(0,255,136,.1)]"
                      : "border-[#00ff88]/10 bg-black/30 hover:border-[#00ff88]/25"
                  }`}
                >
                  <span className="text-lg">{f.icon}</span>
                  <p className="mt-1 text-[10px] font-bold text-zinc-400">{f.label}</p>
                </button>
              ))}
            </div>
          </div>

          <div>
            <p className="mb-3 text-[10px] font-bold tracking-[0.15em] text-zinc-500 uppercase">Include Sections</p>
            <div className="grid gap-2 sm:grid-cols-2">
              {SECTIONS.map((section) => (
                <label
                  key={section.id}
                  className="flex cursor-pointer items-center gap-2.5 rounded-lg border border-[#00ff88]/8 bg-black/20 px-3 py-2.5 transition hover:border-[#00ff88]/20"
                >
                  <input
                    type="checkbox"
                    className="h-3.5 w-3.5 accent-[#00ff88]"
                    checked={sections[section.id]}
                    onChange={() => toggleSection(section.id)}
                    disabled={reportType !== "custom"}
                  />
                  <span className="text-xs text-zinc-400">{section.label}</span>
                </label>
              ))}
            </div>
            {reportType !== "custom" && (
              <p className="mt-2 text-[10px] text-zinc-600">All sections included for {REPORT_TYPES.find((t) => t.id === reportType)?.label}</p>
            )}
          </div>
        </div>

        <div className="border-t border-[#00ff88]/10 px-6 py-4">
          <button
            type="button"
            className="tmgc-btn-primary flex w-full items-center justify-center gap-2 rounded-xl px-4 py-3.5 text-sm tracking-wide disabled:opacity-40"
            disabled={generating}
            onClick={handleGenerate}
          >
            {generating ? "Generating..." : "Generate Report →"}
          </button>
        </div>
      </div>
    </div>
  );
}
