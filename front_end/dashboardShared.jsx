import React from "react";

export const RAW_TABS = ["dig", "mx", "ip_whois", "domain_whois", "ssl", "curl", "nc"];

export const KEYWORDS = [
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

export function Dot({ enabled }) {
  return (
    <span
      className={`inline-block h-2.5 w-2.5 rounded-full ${
        enabled ? "bg-green-400 shadow-[0_0_10px_rgba(74,222,128,0.9)]" : "animate-pulse bg-red-500 shadow-[0_0_10px_rgba(239,68,68,0.9)]"
      }`}
    />
  );
}

export function Matrix({ label, value }) {
  return (
    <div className="rounded-lg border border-green-950/50 bg-black/30 p-3">
      <span className="block text-[10px] font-bold tracking-wider text-green-800">{label}</span>
      <strong className="break-words text-sm text-green-300">{value || "N/A"}</strong>
    </div>
  );
}

export function HeaderBadge({ header }) {
  const status = header.status || header.strength || (header.enabled ? "STRONG" : "MISSING");
  const colors = {
    STRONG: "text-green-400",
    GOOD: "text-green-400",
    WEAK: "text-yellow-300",
    MISCONFIGURED: "text-red-400",
    REPORT_ONLY: "text-yellow-300",
    DEPRECATED: "text-gray-300",
    OPTIONAL: "text-cyan-300",
    MISSING: "text-red-400",
  };
  return <span className={`text-xs font-bold ${colors[status] || "text-green-300"}`}>{status.replace(/_/g, " ")}</span>;
}

export function ExportButton({ disabled, onClick, label }) {
  return (
    <button
      type="button"
      className="rounded-lg border border-green-500/40 px-2 py-3 text-xs font-bold text-green-300 transition hover:bg-green-500/10 disabled:opacity-40"
      disabled={disabled}
      onClick={onClick}
    >
      {label}
    </button>
  );
}

export function HighlightedText({ text }) {
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

function escapeRegex(text) {
  return text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
