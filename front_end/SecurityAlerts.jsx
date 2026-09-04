import React from "react";

const SEVERITY_STYLES = {
  high: { label: "High", className: "bg-red-500/15 text-red-400 border-red-500/30" },
  medium: { label: "Medium", className: "bg-yellow-500/15 text-yellow-400 border-yellow-500/30" },
  low: { label: "Low", className: "bg-green-500/15 text-green-400 border-green-500/30" },
  info: { label: "Info", className: "bg-blue-500/15 text-blue-400 border-blue-500/30" },
};

const STATUS_STYLES = {
  new: "text-[#00ff88]",
  investigating: "text-yellow-400",
  resolved: "text-zinc-500",
};

function formatTimeAgo(timestamp) {
  if (!timestamp) return "—";
  const diff = Date.now() - timestamp;
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return "Just now";
  if (mins < 60) return `${mins}m ago`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours}h ago`;
  return `${Math.floor(hours / 24)}d ago`;
}

function inferSeverity(finding, riskScore) {
  if (/CRITICAL|MALWARE|PHISHING|HIGH RISK/i.test(finding) || riskScore >= 71) return "high";
  if (/MEDIUM|SUSPICIOUS|SSL|EXPOSED|DEAD HOST/i.test(finding) || riskScore >= 26) return "medium";
  if (/LOW|INFO|HEADER/i.test(finding)) return "low";
  return riskScore >= 46 ? "medium" : "info";
}

function inferAlertName(finding) {
  if (/MALWARE/i.test(finding)) return "Malware Detected";
  if (/PHISHING/i.test(finding)) return "Phishing Indicators";
  if (/TYPOSQUAT/i.test(finding)) return "Typosquatting Detected";
  if (/SSL/i.test(finding)) return "SSL Certificate Issue";
  if (/EXPOSED PORT/i.test(finding)) return "Exposed Port Found";
  if (/SUBDOMAIN/i.test(finding)) return "New Subdomain Discovered";
  if (/BRAND|IMPERSONAT/i.test(finding)) return "Brand Impersonation";
  if (/ML ANALYSIS/i.test(finding)) return "ML Threat Signal";
  const short = finding.split(/[.:]/)[0]?.trim();
  return short?.length > 40 ? `${short.slice(0, 38)}…` : short || "Security Finding";
}

export function buildAlertsFromHistory(scanHistory = [], currentData = null) {
  const alerts = [];

  scanHistory.forEach((scan, index) => {
    const findings = scan.findings || [];
    if (findings.length === 0 && scan.risk_score >= 26) {
      alerts.push({
        id: `scan-${scan.domain}-${scan.completedAt}`,
        severity: scan.risk_score >= 71 ? "high" : scan.risk_score >= 46 ? "medium" : "low",
        alert: scan.risk_score >= 71 ? "Malware Detected" : scan.risk_score >= 46 ? "High Risk Domain" : "Suspicious Activity",
        target: scan.domain,
        time: scan.completedAt,
        status: index === 0 ? "new" : "investigating",
      });
      return;
    }

    findings.slice(0, 3).forEach((finding, fi) => {
      alerts.push({
        id: `${scan.domain}-${scan.completedAt}-${fi}`,
        severity: inferSeverity(finding, scan.risk_score),
        alert: inferAlertName(finding),
        target: scan.domain,
        time: scan.completedAt,
        status: index === 0 && fi === 0 ? "new" : index < 2 ? "investigating" : "resolved",
      });
    });
  });

  if (currentData?.findings?.length) {
    const exists = alerts.some((a) => a.target === currentData.domain);
    if (!exists) {
      currentData.findings.slice(0, 2).forEach((finding, fi) => {
        alerts.push({
          id: `current-${fi}`,
          severity: inferSeverity(finding, currentData.risk_score),
          alert: inferAlertName(finding),
          target: currentData.domain,
          time: Date.now(),
          status: "new",
        });
      });
    }
  }

  return alerts
    .sort((a, b) => (b.time || 0) - (a.time || 0))
    .slice(0, 12);
}

export default function SecurityAlerts({ alerts = [], onViewAlert }) {
  if (!alerts.length) {
    return (
      <div className="flex flex-col items-center justify-center rounded-xl border border-dashed border-[#00ff88]/10 py-12 text-center">
        <p className="text-sm text-zinc-500">No security alerts yet</p>
        <p className="mt-1 text-[11px] text-zinc-600">Alerts appear automatically when threats are detected during scans</p>
      </div>
    );
  }

  return (
    <div className="overflow-x-auto rounded-xl border border-[#00ff88]/8">
      <table className="w-full min-w-[640px] text-left text-xs">
        <thead>
          <tr className="border-b border-[#00ff88]/10 bg-black/40 text-[10px] font-bold tracking-[0.12em] text-zinc-500 uppercase">
            <th className="px-4 py-3">Severity</th>
            <th className="px-4 py-3">Alert</th>
            <th className="px-4 py-3">Target</th>
            <th className="px-4 py-3">Time</th>
            <th className="px-4 py-3">Status</th>
            <th className="px-4 py-3 text-right">Actions</th>
          </tr>
        </thead>
        <tbody>
          {alerts.map((alert) => {
            const sev = SEVERITY_STYLES[alert.severity] || SEVERITY_STYLES.info;
            return (
              <tr key={alert.id} className="border-b border-[#00ff88]/5 transition hover:bg-[#00ff88]/3">
                <td className="px-4 py-3">
                  <span className={`inline-flex rounded-full border px-2.5 py-0.5 text-[10px] font-bold uppercase ${sev.className}`}>
                    {sev.label}
                  </span>
                </td>
                <td className="px-4 py-3 font-medium text-zinc-300">{alert.alert}</td>
                <td className="px-4 py-3 font-mono text-zinc-400">{alert.target}</td>
                <td className="px-4 py-3 text-zinc-500">{formatTimeAgo(alert.time)}</td>
                <td className={`px-4 py-3 font-semibold capitalize ${STATUS_STYLES[alert.status] || "text-zinc-500"}`}>
                  {alert.status}
                </td>
                <td className="px-4 py-3 text-right">
                  <button
                    type="button"
                    className="rounded-lg border border-[#00ff88]/20 px-3 py-1 text-[10px] font-bold text-[#00ff88]/80 transition hover:border-[#00ff88]/40 hover:bg-[#00ff88]/8"
                    onClick={() => onViewAlert?.(alert)}
                  >
                    View
                  </button>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
