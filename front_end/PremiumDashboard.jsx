import React from "react";
import { Dot, ExportButton, HeaderBadge, HighlightedText, Matrix, RAW_TABS } from "./dashboardShared.jsx";

export default function PremiumDashboard({
  user,
  target,
  setTarget,
  logs,
  data,
  loading,
  loadingAI,
  error,
  activeTab,
  setActiveTab,
  aiReport,
  currentView,
  exportOpen,
  setExportOpen,
  sidebarOpen,
  setSidebarOpen,
  scanMeta,
  headerRows,
  verdict,
  accent,
  exportRef,
  analyze,
  runAIAnalysis,
  exportExcel,
  exportPdf,
  exportRawTxt,
  exportMarkdown,
  shareReport,
  scrollToSection,
  setUser,
  NAV_ITEMS,
  TMGC_VERSION,
}) {
  const riskScore = data?.risk_score || 0;
  const verdictInfo = getVerdictInfo(riskScore);
  const trustScore = getTrustScore(riskScore);
  const threatCategories = getThreatCategories(data);
  const securityChecks = countSecurityChecks(data, headerRows);
  const threatsDetected = countThreats(data);
  const recommendations = countRecommendations(data, headerRows);
  const confidencePct = getConfidencePercent(data, riskScore);
  const sslValid = data?.parsed_meta?.ssl_issuer && data.parsed_meta.ssl_issuer !== "N/A";

  return (
    <div className="tmgc-root min-h-screen bg-[#030303] text-zinc-300">
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap');
        .tmgc-root { font-family: 'Inter', system-ui, sans-serif; }
        .tmgc-mono { font-family: 'JetBrains Mono', ui-monospace, monospace; }
        @keyframes tmgc-pulse { 0%, 100% { opacity: 1; box-shadow: 0 0 8px rgba(34,197,94,.8); } 50% { opacity: .7; box-shadow: 0 0 16px rgba(34,197,94,.4); } }
        @keyframes tmgc-glow { 0%, 100% { filter: drop-shadow(0 0 8px rgba(34,197,94,.45)); } 50% { filter: drop-shadow(0 0 18px rgba(34,197,94,.7)); } }
        .tmgc-card { background: linear-gradient(145deg, rgba(12,12,12,.95), rgba(6,6,6,.98)); border: 1px solid rgba(34,197,94,.15); box-shadow: 0 0 30px rgba(0,0,0,.5), inset 0 1px 0 rgba(255,255,255,.03); }
        .tmgc-card:hover { border-color: rgba(34,197,94,.28); }
        .tmgc-nav-active { background: linear-gradient(90deg, rgba(34,197,94,.18), transparent); border-left: 3px solid #22c55e; color: #4ade80; }
        .tmgc-grid-bg { background-image: radial-gradient(rgba(34,197,94,.04) 1px, transparent 1px); background-size: 24px 24px; }
        .intel-keyword { color: #f87171; font-weight: 700; text-shadow: 0 0 8px rgba(248,113,113,.6); }
        .tmgc-scrollbar::-webkit-scrollbar { width: 5px; }
        .tmgc-scrollbar::-webkit-scrollbar-thumb { background: rgba(34,197,94,.25); border-radius: 4px; }
      `}</style>

      {sidebarOpen && (
        <button type="button" className="fixed inset-0 z-40 bg-black/60 lg:hidden" onClick={() => setSidebarOpen(false)} aria-label="Close sidebar" />
      )}

      <aside className={`fixed inset-y-0 left-0 z-50 flex w-[260px] flex-col border-r border-green-900/30 bg-[#050505]/95 backdrop-blur-xl transition-transform duration-300 lg:translate-x-0 ${sidebarOpen ? "translate-x-0" : "-translate-x-full"}`}>
        <div className="border-b border-green-900/30 px-5 py-6">
          <div className="flex items-center gap-2">
            <div className="flex h-9 w-9 items-center justify-center rounded-lg border border-green-500/40 bg-green-500/10 text-lg font-black text-green-400 shadow-[0_0_20px_rgba(34,197,94,.25)]">T</div>
            <div>
              <p className="text-lg font-extrabold tracking-wide text-green-400">TMGC</p>
              <p className="text-[10px] font-semibold tracking-[0.2em] text-green-700">FORENSIC PIPELINE</p>
            </div>
          </div>
        </div>

        <nav className="tmgc-scrollbar flex-1 space-y-0.5 overflow-y-auto px-3 py-4">
          {NAV_ITEMS.map((item) => (
            <button
              key={item.id}
              type="button"
              onClick={() => scrollToSection(item.id)}
              className={`flex w-full items-center gap-3 rounded-r-lg px-3 py-2.5 text-left text-sm transition-all duration-200 hover:bg-green-500/5 hover:text-green-300 ${currentView === item.id ? "tmgc-nav-active font-semibold" : "text-zinc-500"}`}
            >
              <NavIcon name={item.icon} active={currentView === item.id} />
              {item.label}
            </button>
          ))}
        </nav>

        <div className="border-t border-green-900/30 p-4">
          <div className="tmgc-card rounded-xl p-4">
            <p className="text-[10px] font-bold tracking-[0.15em] text-zinc-500">SYSTEM STATUS</p>
            <div className="mt-2 flex items-center gap-2">
              <span className="h-2 w-2 rounded-full bg-green-400" style={{ animation: "tmgc-pulse 2s infinite" }} />
              <span className="text-sm font-medium text-green-400">All Systems Operational</span>
            </div>
            <p className="mt-3 text-[11px] text-zinc-500">Threat Intel Feed</p>
            <p className="text-[11px] text-zinc-600">{scanMeta.completedAt ? new Date(scanMeta.completedAt).toLocaleString() : "Awaiting scan"}</p>
            <p className="mt-3 text-[10px] font-semibold tracking-wider text-green-800">{TMGC_VERSION}</p>
          </div>
        </div>
      </aside>

      <div className="lg:pl-[260px]">
        <header className="sticky top-0 z-30 border-b border-green-900/30 bg-[#030303]/90 backdrop-blur-xl">
          <div className="flex flex-wrap items-center gap-3 px-4 py-4 lg:px-6">
            <button type="button" className="rounded-lg border border-green-900/40 p-2 text-green-400 lg:hidden" onClick={() => setSidebarOpen(true)} aria-label="Open menu">
              <svg className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 6h16M4 12h16M4 18h16" /></svg>
            </button>

            <div className="min-w-0 flex-1">
              <label className="mb-1 block text-[10px] font-bold tracking-[0.2em] text-green-700">ANALYZE DOMAIN / URL</label>
              <div className="flex flex-col gap-2 sm:flex-row">
                <input
                  className="w-full rounded-lg border border-green-900/50 bg-black/60 px-4 py-2.5 text-sm text-green-100 outline-none transition focus:border-green-500/60 focus:shadow-[0_0_20px_rgba(34,197,94,.12)] placeholder:text-green-950"
                  value={target}
                  onChange={(e) => setTarget(e.target.value)}
                  onKeyDown={(e) => e.key === "Enter" && analyze()}
                  placeholder="https://example.com"
                />
                <button
                  type="button"
                  className="flex shrink-0 items-center justify-center gap-2 rounded-lg border border-green-500/60 bg-green-500/10 px-6 py-2.5 text-sm font-bold tracking-wide text-green-400 transition hover:bg-green-500/20 hover:shadow-[0_0_24px_rgba(34,197,94,.2)] disabled:opacity-40"
                  disabled={loading}
                  onClick={analyze}
                >
                  <svg className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor"><circle cx="12" cy="12" r="9" strokeWidth={2} /><circle cx="12" cy="12" r="3" strokeWidth={2} /><path strokeLinecap="round" strokeWidth={2} d="M12 3v3M12 18v3" /></svg>
                  {loading ? "ANALYZING..." : "ANALYZE"}
                </button>
              </div>
            </div>

            <div className="flex items-center gap-2">
              <div className="relative" ref={exportRef}>
                <button
                  type="button"
                  className="flex items-center gap-2 rounded-lg border border-green-900/40 bg-black/40 px-4 py-2.5 text-xs font-semibold text-green-300 transition hover:border-green-500/40 disabled:opacity-40"
                  disabled={!data}
                  onClick={() => setExportOpen((v) => !v)}
                >
                  <svg className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 10v6m0 0l-3-3m3 3l3-3M4 16v2a2 2 0 002 2h12a2 2 0 002-2v-2" /></svg>
                  Export Report
                  <svg className="h-3 w-3" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" /></svg>
                </button>
                {exportOpen && (
                  <div className="absolute right-0 top-full z-50 mt-2 w-52 overflow-hidden rounded-lg border border-green-900/40 bg-[#0a0a0a] shadow-xl">
                    <button type="button" className="block w-full px-4 py-2.5 text-left text-xs text-green-300 hover:bg-green-500/10" onClick={() => { exportExcel(); setExportOpen(false); }}>Excel Report (.xlsx)</button>
                    <button type="button" className="block w-full px-4 py-2.5 text-left text-xs text-green-300 hover:bg-green-500/10" onClick={() => { exportPdf(); setExportOpen(false); }}>PDF Dossier (.pdf)</button>
                    <button type="button" className="block w-full px-4 py-2.5 text-left text-xs text-green-300 hover:bg-green-500/10" onClick={() => { exportRawTxt(); setExportOpen(false); }}>Raw TXT Log (.txt)</button>
                    <button type="button" className="block w-full px-4 py-2.5 text-left text-xs text-green-300 hover:bg-green-500/10" onClick={() => { exportMarkdown(); setExportOpen(false); }}>Markdown Log (.md)</button>
                  </div>
                )}
              </div>
              <button type="button" className="flex items-center gap-2 rounded-lg border border-green-900/40 bg-black/40 px-4 py-2.5 text-xs font-semibold text-green-300 transition hover:border-green-500/40 disabled:opacity-40" disabled={!data} onClick={shareReport}>
                <svg className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8.684 13.342C8.886 12.938 9 12.482 9 12c0-.482-.114-.938-.316-1.342m0 2.684a3 3 0 110-2.684m0 2.684l6.632 3.316m-6.632-6l6.632-3.316m0 0a3 3 0 105.367-2.684 3 3 0 00-5.367 2.684zm0 9.316a3 3 0 105.368 2.684 3 3 0 00-5.368-2.684z" /></svg>
                Share
              </button>
              <div className="hidden items-center gap-2 rounded-lg border border-green-900/30 px-3 py-2 text-xs text-zinc-500 md:flex">
                <span className="max-w-[120px] truncate text-green-600">{user.email}</span>
                <button type="button" className="text-red-400 hover:text-red-300" onClick={() => { localStorage.removeItem("tmgc_user"); setUser(null); }}>Logout</button>
              </div>
            </div>
          </div>
          {error && <div className="mx-4 mb-4 rounded-lg border border-red-500/40 bg-red-950/20 px-4 py-3 text-sm text-red-400 lg:mx-6">{error}</div>}
        </header>

        <main className="tmgc-grid-bg space-y-4 p-4 lg:p-6">
          <div id="dashboard" className="grid gap-4 xl:grid-cols-2">
            <section className={`tmgc-card rounded-2xl p-6 ${verdictInfo.glow}`}>
              <div className="grid gap-6 md:grid-cols-[1fr_auto_1fr]">
                <div>
                  <div className="flex items-start gap-3">
                    <div className={`rounded-xl border p-3 ${verdictInfo.iconBg}`} style={{ animation: riskScore < 30 ? "tmgc-glow 3s infinite" : undefined }}>
                      <svg className={`h-8 w-8 ${verdictInfo.iconColor}`} fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" /></svg>
                    </div>
                    <div>
                      <h2 className={`text-2xl font-extrabold tracking-tight md:text-3xl ${verdictInfo.titleColor}`}>{verdictInfo.title}</h2>
                      <p className="mt-1 text-sm text-zinc-500">{verdictInfo.subtitle}</p>
                      <div className="mt-3 flex flex-wrap gap-2">
                        {verdictInfo.badges.map((badge) => (
                          <span key={badge} className="rounded-full border border-green-900/40 bg-green-500/5 px-3 py-1 text-[11px] font-semibold text-green-400">{badge}</span>
                        ))}
                      </div>
                    </div>
                  </div>
                </div>
                <TrustGauge score={data ? trustScore : null} riskScore={riskScore} hasData={Boolean(data)} />
                <div className="space-y-3 text-sm">
                  <MetaRow label="Scan Time" value={scanMeta.completedAt ? new Date(scanMeta.completedAt).toLocaleString() : loading ? "In progress..." : "—"} />
                  <MetaRow label="Domain Age" value={data?.parsed_meta?.domain_age || "—"} />
                  <MetaRow label="Last Updated" value={scanMeta.completedAt ? new Date(scanMeta.completedAt).toLocaleString() : "—"} />
                  <MetaRow label="Scan Duration" value={scanMeta.durationMs ? formatDuration(scanMeta.durationMs) : loading ? "Running..." : "—"} />
                  <MetaRow label="Confidence" value={confidencePct != null ? `High ${confidencePct}%` : "—"} highlight />
                </div>
              </div>
            </section>

            <section id="threat-analysis" className="tmgc-card rounded-2xl p-6">
              <div className="mb-4 flex items-center justify-between">
                <h3 className="text-sm font-bold tracking-[0.15em] text-green-500">THREAT SCORE BREAKDOWN</h3>
                <span className="text-xs text-zinc-600">Radar Analysis</span>
              </div>
              <div className="grid gap-4 md:grid-cols-2">
                <RadarChart categories={threatCategories} />
                <div className="space-y-2">
                  {threatCategories.map((cat) => (
                    <div key={cat.name} className="flex items-center justify-between rounded-lg border border-green-950/50 bg-black/30 px-3 py-2">
                      <div className="flex items-center gap-2">
                        <span className="h-2 w-2 rounded-sm" style={{ backgroundColor: cat.color }} />
                        <span className="text-sm text-zinc-400">{cat.name}</span>
                      </div>
                      <div className="text-right">
                        <span className="text-sm font-bold text-zinc-200">{cat.score}/100</span>
                        <span className={`ml-2 text-[10px] font-semibold ${cat.levelClass}`}>{cat.level}</span>
                      </div>
                    </div>
                  ))}
                  <div className="mt-3 flex items-center justify-between border-t border-green-900/30 pt-3">
                    <span className="text-xs font-bold tracking-wider text-zinc-500">OVERALL SCORE</span>
                    <span className={`text-xl font-black ${data ? (riskScore >= 60 ? "text-red-400" : riskScore >= 30 ? "text-yellow-400" : "text-green-400") : "text-zinc-600"}`}>{data ? `${riskScore}/100` : "—/100"}</span>
                  </div>
                </div>
              </div>
            </section>
          </div>

          <div className="grid gap-4 lg:grid-cols-3">
            <section id="domain-intelligence" className="tmgc-card rounded-2xl p-6 lg:col-span-2">
              <h3 className="mb-4 text-sm font-bold tracking-[0.15em] text-green-500">OVERVIEW</h3>
              <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
                <OverviewTile icon="globe" label="Domain" value={data?.domain || target || "—"} />
                <OverviewTile icon="ip" label="IP Address" value={data?.ip_address || "—"} />
                <OverviewTile icon="location" label="Location" value={data?.parsed_meta?.country || "—"} sub={data?.parsed_meta?.asn} />
                <OverviewTile icon="shield" label="Reputation" value={data ? verdictInfo.title : "—"} />
              </div>
              <div className="mt-5 rounded-xl border border-green-950/40 bg-black/30 p-4">
                <p className="text-[10px] font-bold tracking-[0.15em] text-green-700">QUICK SUMMARY</p>
                <p className="mt-2 text-sm leading-relaxed text-zinc-400">
                  {data ? getQuickSummary(data, riskScore) : "Run an analysis to generate a forensic summary for this target."}
                </p>
                <div className="mt-4 grid gap-3 sm:grid-cols-3">
                  <StatBox label="Security Checks Passed" value={data ? securityChecks : "—"} tone="green" />
                  <StatBox label="Threats Detected" value={data ? threatsDetected : "—"} tone={threatsDetected > 0 ? "red" : "green"} />
                  <StatBox label="Recommendations" value={data ? recommendations : "—"} tone="yellow" />
                </div>
              </div>
            </section>

            <section className="tmgc-card rounded-2xl p-6">
              <div className="mb-4 flex items-center justify-between">
                <h3 className="text-sm font-bold tracking-[0.15em] text-green-500">SECURITY HEADERS</h3>
                <span className="text-[10px] text-green-700">{headerRows.filter((h) => h.effective ?? h.enabled).length}/{headerRows.length}</span>
              </div>
              <div className="tmgc-scrollbar max-h-[280px] space-y-2 overflow-y-auto">
                {headerRows.slice(0, 8).map((header) => (
                  <div key={header.name} className="flex items-center justify-between gap-2 rounded-lg border border-green-950/40 bg-black/20 px-3 py-2">
                    <span className="truncate text-xs text-zinc-400">{header.name}</span>
                    <span className="flex shrink-0 items-center gap-2">
                      <Dot enabled={header.effective ?? header.enabled} />
                      <HeaderBadge header={header} />
                    </span>
                  </div>
                ))}
              </div>
              <button type="button" className="mt-3 text-xs font-semibold text-green-600 hover:text-green-400" onClick={() => scrollToSection("reports")}>View All Headers →</button>
            </section>
          </div>

          <div className="grid gap-4 lg:grid-cols-2">
            <section id="ssl-analysis" className="tmgc-card rounded-2xl p-6">
              <div className="flex items-start gap-4">
                <div className={`rounded-xl border p-3 ${sslValid ? "border-green-500/30 bg-green-500/10" : "border-red-500/30 bg-red-500/10"}`}>
                  <svg className={`h-7 w-7 ${sslValid ? "text-green-400" : "text-red-400"}`} fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" /></svg>
                </div>
                <div className="flex-1">
                  <h3 className="text-sm font-bold tracking-[0.15em] text-green-500">SSL/TLS ANALYSIS</h3>
                  <p className={`mt-1 text-lg font-bold ${sslValid ? "text-green-400" : "text-red-400"}`}>{sslValid ? "Valid SSL Certificate" : "SSL Issues Detected"}</p>
                  <div className="mt-4 grid gap-2 text-sm sm:grid-cols-2">
                    <MetaRow label="Issuer" value={data?.parsed_meta?.ssl_issuer || "—"} compact />
                    <MetaRow label="Valid From" value={data?.ssl_dates?.not_before || "—"} compact />
                    <MetaRow label="Valid To" value={data?.ssl_dates?.not_after || "—"} compact />
                    <MetaRow label="Protocol" value={data?.ssl_protocol || "—"} compact />
                  </div>
                  <button type="button" className="mt-3 text-xs font-semibold text-green-600 hover:text-green-400" onClick={() => { setActiveTab("ssl"); scrollToSection("reports"); }}>View Certificate Details →</button>
                </div>
              </div>
            </section>

            <section id="forensic-logs" className="tmgc-card rounded-2xl p-0 overflow-hidden">
              <div className="flex items-center justify-between border-b border-green-900/30 px-5 py-3">
                <h3 className="text-sm font-bold tracking-[0.15em] text-green-500">FORENSIC PIPELINE LOGS</h3>
                <span className="flex items-center gap-1.5 rounded-full border border-green-500/30 bg-green-500/10 px-2 py-0.5 text-[10px] font-bold text-green-400">
                  <span className="h-1.5 w-1.5 rounded-full bg-green-400 animate-pulse" /> LIVE
                </span>
              </div>
              <div className="tmgc-mono tmgc-scrollbar h-[220px] overflow-y-auto bg-[#020802]/80 p-4 text-xs leading-6 text-green-500/90">
                {logs.map((line, index) => (
                  <p key={`${line}-${index}`} className="drop-shadow-[0_0_4px_rgba(34,197,94,.3)]">
                    {line.includes("FAILURE") || line.includes("!!") ? <span className="text-red-400">{line}</span> : line.includes(">>") ? <>{" "}{line.replace(">>", "[PASS] >>")}</> : line}
                  </p>
                ))}
              </div>
            </section>
          </div>

          <div className="grid gap-4 lg:grid-cols-3">
            <section id="whois-lookup" className="tmgc-card rounded-2xl p-6">
              <h3 className="mb-4 text-sm font-bold tracking-[0.15em] text-green-500">DOMAIN INFORMATION</h3>
              <div className="space-y-3 text-sm">
                <DomainRow label="Registrar" value={data?.parsed_meta?.registrar} />
                <DomainRow label="Registered" value={data?.parsed_meta?.created_date} />
                <DomainRow label="Updated" value={data?.parsed_meta?.updated_date} />
                <DomainRow label="Expiry" value={data?.parsed_meta?.expiry_date} />
                <DomainRow label="Nameservers" value={data?.nameservers?.length ? data.nameservers.join(", ") : "—"} />
                <DomainRow label="DNSSEC" value={data?.dnssec || "—"} />
                <DomainRow label="Domain Status" value={data ? (riskScore < 30 ? "Active" : riskScore < 60 ? "Review" : "Flagged") : "—"} />
              </div>
              <button type="button" className="mt-4 text-xs font-semibold text-green-600 hover:text-green-400" onClick={() => { setActiveTab("domain_whois"); scrollToSection("reports"); }}>View WHOIS Details →</button>
            </section>

            <section id="content-analysis" className="tmgc-card rounded-2xl p-6">
              <div className="mb-4 flex items-center justify-between">
                <h3 className="text-sm font-bold tracking-[0.15em] text-green-500">AI ANALYSIS</h3>
                <button
                  type="button"
                  className="rounded-lg border border-cyan-500/40 bg-cyan-500/10 px-3 py-1.5 text-[10px] font-bold text-cyan-300 transition hover:bg-cyan-500/20 disabled:opacity-40"
                  disabled={loadingAI || !data}
                  onClick={runAIAnalysis}
                >
                  {loadingAI ? "RUNNING..." : "RUN AI ANALYSIS"}
                </button>
              </div>
              {loadingAI ? (
                <p className="text-sm text-cyan-400">Running AI threat reasoning...</p>
              ) : aiReport ? (
                <div className="tmgc-scrollbar max-h-[200px] overflow-y-auto text-sm leading-relaxed text-cyan-100/80 whitespace-pre-wrap">
                  <HighlightedText text={aiReport.formatted_report || aiReport.analysis || aiReport.report || JSON.stringify(aiReport, null, 2)} />
                </div>
              ) : (
                <div className="space-y-2 text-sm text-zinc-500">
                  <p>Click RUN AI ANALYSIS for deep contextual cyber reasoning.</p>
                  <p className="text-xs text-yellow-600/80">ML engine and heuristic scoring remain active if AI is unavailable.</p>
                  {data?.ai_verdict && <p className="mt-2 text-xs text-zinc-400">{data.ai_verdict.slice(0, 280)}{data.ai_verdict.length > 280 ? "..." : ""}</p>}
                </div>
              )}
              <div className="mt-4">
                <div className="mb-1 flex justify-between text-[10px] text-zinc-500"><span>AI Confidence</span><span>{confidencePct != null ? `${confidencePct}%` : "—"}</span></div>
                <div className="h-1.5 overflow-hidden rounded-full bg-green-950/50">
                  <div className="h-full rounded-full bg-gradient-to-r from-green-600 to-green-400 transition-all duration-700" style={{ width: `${confidencePct || 0}%` }} />
                </div>
              </div>
            </section>

            <section id="reputation" className="tmgc-card rounded-2xl p-6">
              <h3 className="mb-4 text-sm font-bold tracking-[0.15em] text-green-500">RISK CONTRIBUTORS</h3>
              <div className="tmgc-scrollbar max-h-[220px] space-y-2 overflow-y-auto">
                {data?.findings?.length ? (
                  data.findings.slice(0, 6).map((finding, index) => {
                    const impact = getFindingImpact(finding);
                    return (
                      <div key={index} className="rounded-lg border border-green-950/40 bg-black/20 px-3 py-2">
                        <span className={`text-[10px] font-bold ${impact.className}`}>{impact.label}</span>
                        <p className="mt-1 text-xs text-zinc-400">{finding}</p>
                      </div>
                    );
                  })
                ) : (
                  <p className="text-sm text-zinc-500">No significant contributors.</p>
                )}
              </div>
              <p className="mt-3 text-xs text-green-700">{threatsDetected === 0 && data ? "No high risk factors detected." : ""}</p>
            </section>
          </div>

          <section id="ip-network" className="grid gap-3 sm:grid-cols-2 lg:grid-cols-5">
            {[
              { id: "ip-network", icon: "network", title: "IP & NETWORK", desc: "Analyze IP reputation", tab: "ip_whois" },
              { id: "dns-records", icon: "dns", title: "DNS RECORDS", desc: "View DNS configuration", tab: "dig" },
              { id: "content-analysis", icon: "file", title: "CONTENT ANALYSIS", desc: "Inspect page content", tab: "curl" },
              { id: "reputation", icon: "star", title: "REPUTATION LOOKUP", desc: "Check threat feeds", tab: "nc" },
              { id: "reports", icon: "report", title: "REPORTS", desc: "Export forensic dossier", tab: null },
            ].map((card) => (
              <button
                key={card.title}
                type="button"
                onClick={() => { if (card.tab) setActiveTab(card.tab); scrollToSection(card.id); }}
                className="tmgc-card group flex items-center justify-between rounded-xl p-4 text-left transition hover:border-green-500/40 hover:shadow-[0_0_24px_rgba(34,197,94,.08)]"
              >
                <div>
                  <NavIcon name={card.icon} active={false} className="mb-2" />
                  <p className="text-xs font-bold tracking-wide text-green-400">{card.title}</p>
                  <p className="mt-1 text-[11px] text-zinc-600">{card.desc}</p>
                </div>
                <svg className="h-4 w-4 text-green-800 transition group-hover:translate-x-0.5 group-hover:text-green-500" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" /></svg>
              </button>
            ))}
          </section>

          <section id="reports" className="tmgc-card rounded-2xl p-6">
            <span id="saved-scans" className="sr-only">Saved scans</span>
            <h3 className="mb-4 text-sm font-bold tracking-[0.15em] text-green-500">DETAILED ANALYSIS & RAW EVIDENCE</h3>
            <div className="grid gap-4 xl:grid-cols-2">
              <div className={`rounded-xl border p-4 ${accent}`}>
                <h4 className="border-b border-green-900/30 pb-2 text-sm font-bold text-green-400">DATA MATRIX :: {verdict}</h4>
                <div className="mt-4 grid gap-3 text-sm sm:grid-cols-2">
                  <Matrix label="TARGET IP" value={data?.ip_address || "N/A"} />
                  <Matrix label="HOSTING SPACE" value={data?.parsed_meta?.hosting_space || "N/A"} />
                  <Matrix label="DOMAIN AGE" value={data?.parsed_meta?.domain_age || "N/A"} />
                  <Matrix label="ASN / COUNTRY" value={`${data?.parsed_meta?.asn || "N/A"} / ${data?.parsed_meta?.country || "N/A"}`} />
                  <Matrix label="HTTP STATUS" value={data?.parsed_meta?.http_status || "N/A"} />
                  <Matrix label="SSL ISSUER" value={data?.parsed_meta?.ssl_issuer || "N/A"} />
                </div>
                <div className="mt-4 rounded-lg border border-green-950/50 bg-black/30 p-4">
                  <p className="text-[10px] font-bold text-green-700">SCORE BREAKDOWN</p>
                  <div className="mt-2 space-y-2 text-sm">
                    <ScoreRow label="RAW EVIDENCE" value={data?.score_components?.heuristic_analysis} />
                    <ScoreRow label="ML ENGINE" value={data?.score_components?.xgboost_ml ?? "N/A"} />
                    <ScoreRow label="AI ANALYSIS" value={data?.score_components?.ai_analysis ?? "UNAVAILABLE"} />
                    <ScoreRow label="SECURITY HEADERS" value={data?.score_components?.security_headers} />
                    <div className="flex justify-between border-t border-green-900/30 pt-2 font-bold text-cyan-400">
                      <span>FINAL SCORE</span><span>{data?.risk_score ?? "---"}/100</span>
                    </div>
                  </div>
                </div>
              </div>

              <div className="space-y-4">
                <div className="grid grid-cols-2 gap-2">
                  <ExportButton disabled={!data} onClick={exportExcel} label="EXPORT EXCEL" />
                  <ExportButton disabled={!data} onClick={exportPdf} label="DOWNLOAD PDF" />
                  <ExportButton disabled={!data} onClick={exportRawTxt} label="RAW TXT LOG" />
                  <ExportButton disabled={!data} onClick={exportMarkdown} label="EXPORT MD" />
                </div>
                <div className="flex flex-wrap gap-2">
                  {RAW_TABS.map((tab) => (
                    <button key={tab} type="button" className={`rounded border px-2 py-1 text-xs transition ${activeTab === tab ? "border-green-400 bg-green-500 text-black" : "border-green-900/50 text-green-500 hover:border-green-500/50"}`} onClick={() => setActiveTab(tab)}>{tab}</button>
                  ))}
                </div>
                <div className="rounded-xl border border-green-900/30 bg-black/40 p-4">
                  <h4 className="mb-2 text-xs font-bold text-green-500">RAW COMMAND OUTPUT :: {activeTab.toUpperCase()}</h4>
                  <pre className="tmgc-mono tmgc-scrollbar max-h-[200px] overflow-auto whitespace-pre-wrap text-xs text-green-400/80">{data?.raw_logs?.[activeTab] ? data.raw_logs[activeTab].slice(0, 15000) : "NO DATA AVAILABLE"}</pre>
                </div>
              </div>
            </div>

            <div className="mt-4 grid gap-4 lg:grid-cols-2">
              <div className="rounded-xl border border-yellow-900/30 bg-yellow-950/5 p-4">
                <h4 className="mb-2 text-sm font-bold text-yellow-400">ML THREAT ANALYSIS</h4>
                {data?.ml_result?.xgb_available ? (
                  <div className="space-y-2 text-sm text-yellow-100/80">
                    <p><strong>MODEL:</strong> XGBoost</p>
                    <p><strong>VERDICT:</strong> {data.ml_result.xgb_verdict?.toUpperCase()}</p>
                    <p><strong>ML SCORE:</strong> {data.ml_result.xgb_score}/100</p>
                    <ul className="ml-5 list-disc text-xs space-y-1">
                      {data.findings?.filter((x) => x.includes("ML ANALYSIS")).map((item, i) => <li key={i}>{item}</li>)}
                    </ul>
                  </div>
                ) : (
                  <p className="text-sm text-yellow-500/80">ML MODEL UNAVAILABLE</p>
                )}
              </div>
              <div className="rounded-xl border border-green-900/30 bg-black/30 p-4">
                <h4 className="mb-2 text-sm font-bold text-green-400">ALL SECURITY HEADERS</h4>
                <div className="tmgc-scrollbar max-h-[180px] space-y-2 overflow-y-auto">
                  {headerRows.map((header) => (
                    <div key={header.name} className="flex items-center justify-between gap-2 rounded border border-green-950/40 px-2 py-1.5 text-xs">
                      <span className="text-zinc-400">{header.name}</span>
                      <span className="flex items-center gap-2"><Dot enabled={header.effective ?? header.enabled} /><HeaderBadge header={header} /></span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </section>

          <section id="settings" className="tmgc-card rounded-xl p-4 md:hidden">
            <p className="text-xs text-zinc-500">Signed in as {user.email}</p>
            <button type="button" className="mt-2 text-sm text-red-400" onClick={() => { localStorage.removeItem("tmgc_user"); setUser(null); }}>Logout</button>
          </section>
        </main>
      </div>
    </div>
  );
}

function NavIcon({ name, active, className = "" }) {
  const color = active ? "text-green-400" : "text-zinc-600";
  const icons = {
    grid: <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M4 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2V6zM14 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2V6zM4 16a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2v-2zM14 16a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2v-2z" />,
    shield: <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />,
    globe: <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M3.055 11H5a2 2 0 012 2v1a2 2 0 002 2 2 2 0 012 2v2.945M8 3.935V5.5A2.5 2.5 0 0010.5 8h.5a2 2 0 012 2 2 2 0 104 0 2 2 0 012-2h1.064M15 20.488V18a2 2 0 012-2h3.064M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />,
    network: <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9m-9 9a9 9 0 019-9" />,
    search: <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />,
    lock: <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />,
    dns: <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2" />,
    file: <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />,
    star: <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M11.049 2.927c.3-.921 1.603-.921 1.902 0l1.519 4.674a1 1 0 00.95.69h4.915c.969 0 1.371 1.24.588 1.81l-3.976 2.888a1 1 0 00-.363 1.118l1.518 4.674c.3.922-.755 1.688-1.538 1.118l-3.976-2.888a1 1 0 00-1.176 0l-3.976 2.888c-.783.57-1.838-.197-1.538-1.118l1.518-4.674a1 1 0 00-.363-1.118l-3.976-2.888c-.784-.57-.38-1.81.588-1.81h4.914a1 1 0 00.951-.69l1.519-4.674z" />,
    report: <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 17v-2m3 2v-4m3 4v-6m2 10H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />,
    bookmark: <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M5 5a2 2 0 012-2h10a2 2 0 012 2v16l-7-3.5L5 21V5z" />,
    settings: <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z" />,
    ip: <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9m-9 9a9 9 0 019-9" />,
    location: <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M17.657 16.657L13.414 20.9a1.998 1.998 0 01-2.827 0l-4.244-4.243a8 8 0 1111.314 0z M15 11a3 3 0 11-6 0 3 3 0 016 0z" />,
  };
  return (
    <svg className={`h-4 w-4 shrink-0 ${color} ${className}`} fill="none" viewBox="0 0 24 24" stroke="currentColor">
      {icons[name] || icons.grid}
    </svg>
  );
}

function TrustGauge({ score, riskScore, hasData }) {
  const pct = hasData ? Math.max(0, Math.min(100, score)) : 0;
  const circumference = 2 * Math.PI * 54;
  const offset = circumference - (pct / 100) * circumference;
  const stroke = riskScore >= 60 ? "#f87171" : riskScore >= 30 ? "#facc15" : "#22c55e";
  return (
    <div className="flex flex-col items-center justify-center">
      <div className="relative h-36 w-36">
        <svg className="h-full w-full -rotate-90" viewBox="0 0 120 120">
          <circle cx="60" cy="60" r="54" fill="none" stroke="rgba(34,197,94,.08)" strokeWidth="8" />
          <circle cx="60" cy="60" r="54" fill="none" stroke={hasData ? stroke : "rgba(34,197,94,.15)"} strokeWidth="8" strokeLinecap="round" strokeDasharray={circumference} strokeDashoffset={hasData ? offset : circumference} className="transition-all duration-1000" style={hasData ? { filter: `drop-shadow(0 0 8px ${stroke})` } : undefined} />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className="text-3xl font-black text-white">{hasData ? score : "—"}</span>
          <span className="text-[10px] font-bold tracking-wider text-zinc-500">/ 100</span>
        </div>
      </div>
      <p className="mt-2 text-[10px] font-bold tracking-[0.2em] text-green-600">TRUST SCORE</p>
    </div>
  );
}

function RadarChart({ categories }) {
  const size = 180;
  const center = size / 2;
  const maxR = 70;
  const n = categories.length || 6;
  const points = categories.map((cat, i) => {
    const angle = (Math.PI * 2 * i) / n - Math.PI / 2;
    const r = (cat.score / 100) * maxR;
    return `${center + r * Math.cos(angle)},${center + r * Math.sin(angle)}`;
  }).join(" ");
  const rings = [0.25, 0.5, 0.75, 1];
  return (
    <svg width={size} height={size} className="mx-auto">
      {rings.map((ring) => (
        <polygon key={ring} points={categories.map((_, i) => {
          const angle = (Math.PI * 2 * i) / n - Math.PI / 2;
          const r = maxR * ring;
          return `${center + r * Math.cos(angle)},${center + r * Math.sin(angle)}`;
        }).join(" ")} fill="none" stroke="rgba(34,197,94,.12)" strokeWidth="1" />
      ))}
      {categories.map((_, i) => {
        const angle = (Math.PI * 2 * i) / n - Math.PI / 2;
        return <line key={i} x1={center} y1={center} x2={center + maxR * Math.cos(angle)} y2={center + maxR * Math.sin(angle)} stroke="rgba(34,197,94,.15)" strokeWidth="1" />;
      })}
      <polygon points={points} fill="rgba(34,197,94,.15)" stroke="#22c55e" strokeWidth="2" style={{ filter: "drop-shadow(0 0 6px rgba(34,197,94,.4))" }} />
    </svg>
  );
}

function MetaRow({ label, value, highlight, compact }) {
  return (
    <div className={`flex justify-between gap-4 ${compact ? "text-xs" : ""}`}>
      <span className="text-zinc-600">{label}</span>
      <span className={`text-right font-medium ${highlight ? "text-green-400" : "text-zinc-300"}`}>{value || "—"}</span>
    </div>
  );
}

function DomainRow({ label, value }) {
  return (
    <div className="flex justify-between gap-4 border-b border-green-950/30 pb-2">
      <span className="text-zinc-600">{label}</span>
      <span className="max-w-[60%] truncate text-right font-medium text-zinc-300">{value || "—"}</span>
    </div>
  );
}

function OverviewTile({ icon, label, value, sub }) {
  return (
    <div className="rounded-xl border border-green-950/40 bg-black/30 p-4 transition hover:border-green-500/20">
      <NavIcon name={icon} active={false} className="mb-2" />
      <p className="text-[10px] font-bold tracking-wider text-green-800">{label}</p>
      <p className="mt-1 truncate text-sm font-semibold text-zinc-200">{value}</p>
      {sub && <p className="mt-0.5 truncate text-[10px] text-zinc-600">{sub}</p>}
    </div>
  );
}

function StatBox({ label, value, tone }) {
  const tones = { green: "border-green-500/20 text-green-400", red: "border-red-500/20 text-red-400", yellow: "border-yellow-500/20 text-yellow-400" };
  return (
    <div className={`rounded-xl border bg-black/30 p-4 text-center ${tones[tone] || tones.green}`}>
      <p className="text-2xl font-black">{value}</p>
      <p className="mt-1 text-[10px] font-semibold tracking-wide text-zinc-500">{label}</p>
    </div>
  );
}

function ScoreRow({ label, value }) {
  return (
    <div className="flex justify-between text-green-300/80">
      <span>{label}</span>
      <strong>{value ?? "N/A"}</strong>
    </div>
  );
}

export function getTrustScore(riskScore) {
  return Math.max(0, Math.min(100, 100 - (riskScore || 0)));
}

export function getVerdictInfo(riskScore) {
  if (riskScore >= 90) {
    return { title: "MALICIOUS", subtitle: "Critical phishing likelihood detected.", titleColor: "text-red-400", iconColor: "text-red-400", iconBg: "border-red-500/30 bg-red-500/10", glow: "shadow-[0_0_30px_rgba(239,68,68,.12)]", badges: ["Phishing Risk", "Critical"] };
  }
  if (riskScore >= 60) {
    return { title: "HIGH RISK", subtitle: "Multiple suspicious indicators detected.", titleColor: "text-red-400", iconColor: "text-red-400", iconBg: "border-red-500/30 bg-red-500/10", glow: "shadow-[0_0_30px_rgba(239,68,68,.12)]", badges: ["Elevated Risk", "Review Required"] };
  }
  if (riskScore >= 30) {
    return { title: "SUSPICIOUS", subtitle: "Further manual investigation recommended.", titleColor: "text-yellow-400", iconColor: "text-yellow-400", iconBg: "border-yellow-500/30 bg-yellow-500/10", glow: "shadow-[0_0_30px_rgba(250,204,21,.08)]", badges: ["Needs Review", "Medium Confidence"] };
  }
  return { title: "SAFE VERIFIED", subtitle: "No significant threats detected.", titleColor: "text-green-400", iconColor: "text-green-400", iconBg: "border-green-500/30 bg-green-500/10", glow: "shadow-[0_0_30px_rgba(34,197,94,.12)]", badges: ["Trusted Domain", "High Confidence"] };
}

export function getConfidencePercent(data, riskScore) {
  if (!data) return null;
  const ai = data.score_components?.ai_analysis;
  if (typeof ai === "number") return Math.round(ai);
  const base = getTrustScore(riskScore);
  return Math.max(50, Math.min(98, base + (data.ml_result?.xgb_available ? 5 : 0)));
}

export function getThreatCategories(data) {
  const colors = ["#22c55e", "#3b82f6", "#a855f7", "#f59e0b", "#06b6d4", "#ec4899"];
  if (!data) {
    return ["Malware", "Phishing", "Spam", "Suspicious Activity", "Reputation", "Network Security"].map((name, i) => ({ name, score: 0, level: "Low Risk", levelClass: "text-green-500", color: colors[i] }));
  }
  const risk = data.risk_score || 0;
  const heuristic = Number(data.score_components?.heuristic_analysis || 0);
  const headers = Number(data.score_components?.security_headers || 0);
  const ml = Number(data.score_components?.xgboost_ml || 0);
  const findings = data.findings || [];
  const has = (kw) => findings.some((f) => f.toUpperCase().includes(kw));
  const mlVerdict = String(data.ml_result?.xgb_verdict || "").toLowerCase();

  const cats = [
    { name: "Malware", score: has("MALWARE") ? Math.min(100, Math.max(risk, ml || heuristic)) : Math.round(Math.min(risk * 0.35, 20)) },
    { name: "Phishing", score: has("PHISHING") || mlVerdict === "phishing" ? Math.min(100, Math.max(risk * 0.95, ml || heuristic)) : Math.round(Math.min(risk * 0.45, 25)) },
    { name: "Spam", score: has("SPAM") ? Math.min(100, heuristic) : Math.round(Math.min(risk * 0.25, 15)) },
    { name: "Suspicious Activity", score: Math.round(Math.min(100, heuristic || risk * 0.6)) },
    { name: "Reputation", score: ml ? Math.round(ml) : Math.round(Math.min(100, risk * 0.7)) },
    { name: "Network Security", score: Math.round(Math.min(100, headers > 0 ? Math.max(risk * 0.4, 100 - headers * 4) : risk * 0.5)) },
  ];

  return cats.map((cat, i) => {
    const level = cat.score >= 60 ? "High Risk" : cat.score >= 30 ? "Medium Risk" : "Low Risk";
    const levelClass = cat.score >= 60 ? "text-red-400" : cat.score >= 30 ? "text-yellow-400" : "text-green-500";
    return { ...cat, level, levelClass, color: colors[i] };
  });
}

export function countSecurityChecks(data, headerRows) {
  if (!data) return 0;
  const headerPass = headerRows.filter((h) => h.effective ?? h.enabled).length;
  const infraPass = [data.ip_address, data.parsed_meta?.ssl_issuer, data.parsed_meta?.registrar].filter((v) => v && v !== "N/A").length;
  return headerPass + infraPass + (data.ml_result?.xgb_available ? 1 : 0);
}

export function countThreats(data) {
  if (!data?.findings?.length) return 0;
  return data.findings.filter((f) => /PHISHING|MALWARE|HIGH RISK|CRITICAL|TYPOSQUATTING|EXPOSED PORT|DEAD HOST/i.test(f)).length;
}

export function countRecommendations(data, headerRows) {
  if (!data) return 0;
  const headerRecs = headerRows.filter((h) => h.recommendation && h.recommendation !== "N/A").length;
  const findingRecs = (data.findings || []).filter((f) => /MEDIUM RISK|SSL|HEADER|RECOMMEND/i.test(f)).length;
  return headerRecs + findingRecs;
}

export function formatDuration(ms) {
  if (ms < 1000) return `${ms}ms`;
  return `${(ms / 1000).toFixed(1)}s`;
}

function getQuickSummary(data, riskScore) {
  if (riskScore >= 90) return "Critical phishing indicators were identified across multiple forensic signals. Immediate review is recommended.";
  if (riskScore >= 60) return data.findings?.[0] || "High-risk infrastructure patterns detected during the forensic pipeline.";
  if (riskScore >= 30) return "Some suspicious indicators were found. Manual validation against threat intelligence feeds is advised.";
  return "Domain profile appears clean across DNS, SSL, headers, and heuristic checks with no high-confidence malicious signals.";
}

function getFindingImpact(finding) {
  if (/TYPOSQUATTING|PHISHING|MALWARE|HIGH RISK|CRITICAL/i.test(finding)) return { label: "+ HIGH IMPACT", className: "text-red-400" };
  if (/SSL|DEAD HOST|EXPOSED PORT|MEDIUM RISK/i.test(finding)) return { label: "+ MEDIUM IMPACT", className: "text-yellow-400" };
  return { label: "+ LOW IMPACT", className: "text-green-400" };
}
