export const CYBER_COLORS = {
  neon: "#00ff88",
  neonDim: "rgba(0,255,136,0.6)",
  neonGlow: "rgba(0,255,136,0.15)",
  bg: "#0a0a0a",
  bgCard: "rgba(12,14,16,0.95)",
  danger: "#ff4444",
  warning: "#ff8800",
  info: "#4488ff",
  text: "#e8e8e8",
  textMuted: "#888888",
};

export function CyberStyles() {
  return (
    <style>{`
      @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800;900&family=JetBrains+Mono:wght@400;500;600;700&display=swap');
      .tmgc-root {
        font-family: 'Inter', system-ui, sans-serif;
        background:
          radial-gradient(circle at 68% 10%, rgba(0,255,180,.14), transparent 30%),
          radial-gradient(circle at 28% 26%, rgba(0,180,255,.08), transparent 26%),
          linear-gradient(135deg, #020504 0%, #07110f 46%, #020303 100%);
      }
      .tmgc-mono { font-family: 'JetBrains Mono', ui-monospace, monospace; }

      @keyframes tmgc-pulse { 0%, 100% { opacity: 1; box-shadow: 0 0 12px rgba(0,255,136,.9); } 50% { opacity: .7; box-shadow: 0 0 24px rgba(0,255,136,.4); } }
      @keyframes tmgc-glow { 0%, 100% { filter: drop-shadow(0 0 10px rgba(0,255,136,.5)); } 50% { filter: drop-shadow(0 0 24px rgba(0,255,136,.8)); } }
      @keyframes tmgc-fade-in { from { opacity: 0; transform: translateY(12px); } to { opacity: 1; transform: translateY(0); } }
      @keyframes tmgc-slide-up { from { opacity: 0; transform: translateY(20px); } to { opacity: 1; transform: translateY(0); } }
      @keyframes tmgc-border-pulse { 0%, 100% { border-color: rgba(0,255,136,.12); } 50% { border-color: rgba(0,255,136,.35); } }
      @keyframes tmgc-scan-line { 0% { transform: translateY(-100%); } 100% { transform: translateY(100vh); } }
      @keyframes tmgc-float { 0%, 100% { transform: translateY(0); } 50% { transform: translateY(-6px); } }
      @keyframes tmgc-orbit { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }
      @keyframes tmgc-drift { 0%, 100% { transform: translate3d(0,0,0); opacity: .45; } 50% { transform: translate3d(10px,-12px,0); opacity: .9; } }

      .tmgc-card {
        background: linear-gradient(145deg, rgba(11,24,22,.82), rgba(3,8,9,.96));
        border: 1px solid rgba(0,255,170,.14);
        box-shadow: 0 18px 70px -28px rgba(0,0,0,.95), 0 0 0 1px rgba(0,255,170,.04) inset;
        transition: border-color .3s ease, box-shadow .3s ease, transform .25s ease;
        position: relative;
        overflow: hidden;
        backdrop-filter: blur(12px);
      }
      .tmgc-card::before {
        content: '';
        position: absolute;
        top: 0; left: 0; right: 0;
        height: 1px;
        background: linear-gradient(90deg, transparent, rgba(0,255,136,.3), transparent);
        opacity: 0.7;
      }
      .tmgc-card:hover {
        border-color: rgba(0,255,180,.28);
        box-shadow: 0 22px 60px -22px rgba(0,0,0,.95), 0 0 44px -12px rgba(0,255,170,.14), 0 0 0 1px rgba(0,255,136,.06) inset;
        transform: translateY(-2px);
      }

      .tmgc-hero-panel {
        position: relative;
        overflow: hidden;
        min-height: 380px;
        border: 1px solid rgba(0,255,170,.16);
        background:
          radial-gradient(circle at 69% 44%, rgba(0,255,170,.2), transparent 29%),
          radial-gradient(circle at 18% 54%, rgba(0,120,255,.08), transparent 34%),
          linear-gradient(135deg, rgba(4,16,16,.92), rgba(2,5,6,.98));
        box-shadow: 0 28px 100px -44px rgba(0,255,170,.25), 0 0 0 1px rgba(255,255,255,.02) inset;
      }

      .tmgc-hero-panel::before {
        content: '';
        position: absolute;
        inset: 0;
        background-image:
          linear-gradient(rgba(0,255,170,.06) 1px, transparent 1px),
          linear-gradient(90deg, rgba(0,255,170,.06) 1px, transparent 1px);
        background-size: 42px 42px;
        mask-image: radial-gradient(circle at 66% 46%, black, transparent 72%);
        opacity: .7;
      }

      .tmgc-hero-copy { position: relative; z-index: 2; }
      .tmgc-globe-stage { position: relative; min-height: 340px; perspective: 900px; }
      .tmgc-globe-stage::before,
      .tmgc-globe-stage::after {
        content: '';
        position: absolute;
        border: 1px solid rgba(0,255,170,.26);
        border-radius: 999px;
        inset: 11% 15%;
        transform: rotateX(66deg) rotateZ(18deg);
        animation: tmgc-orbit 18s linear infinite;
      }
      .tmgc-globe-stage::after {
        inset: 20% 7%;
        border-color: rgba(0,180,255,.18);
        transform: rotateX(70deg) rotateZ(-26deg);
        animation-duration: 24s;
        animation-direction: reverse;
      }
      .tmgc-signal-card {
        position: absolute;
        z-index: 3;
        border: 1px solid currentColor;
        border-radius: 10px;
        background: rgba(3,10,10,.78);
        padding: 10px 12px;
        box-shadow: 0 0 26px -8px currentColor;
        backdrop-filter: blur(10px);
        animation: tmgc-drift 4.8s ease-in-out infinite;
      }

      .tmgc-nav-active {
        background: linear-gradient(90deg, rgba(0,255,136,.15), transparent);
        border-left: 3px solid #00ff88;
        color: #00ff88;
        box-shadow: inset 0 0 24px -8px rgba(0,255,136,.12);
      }

      .tmgc-grid-bg {
        background-image:
          radial-gradient(rgba(0,255,136,.025) 1px, transparent 1px),
          linear-gradient(180deg, rgba(0,255,136,.01) 0%, transparent 40%);
        background-size: 32px 32px, 100% 100%;
      }

      .intel-keyword { color: #ff6666; font-weight: 700; text-shadow: 0 0 10px rgba(255,68,68,.5); }

      .tmgc-scrollbar::-webkit-scrollbar { width: 4px; }
      .tmgc-scrollbar::-webkit-scrollbar-thumb { background: rgba(0,255,136,.2); border-radius: 4px; }
      .tmgc-scrollbar::-webkit-scrollbar-thumb:hover { background: rgba(0,255,136,.4); }

      .tmgc-section-title {
        font-size: 11px;
        font-weight: 700;
        letter-spacing: 0.18em;
        color: #00ff88;
        display: flex;
        align-items: center;
        gap: 10px;
        margin-bottom: 16px;
        padding-left: 12px;
        border-left: 2px solid rgba(0,255,136,.35);
        text-transform: uppercase;
      }
      .tmgc-section-title-plain {
        font-size: 11px;
        font-weight: 700;
        letter-spacing: 0.18em;
        color: #00ff88;
        text-transform: uppercase;
        margin-bottom: 16px;
      }
      .tmgc-section-title::after,
      .tmgc-section-title-plain::after {
        content: '';
        flex: 1;
        height: 1px;
        background: linear-gradient(90deg, rgba(0,255,136,.2), transparent);
      }

      .tmgc-stat {
        font-size: 32px;
        font-weight: 800;
        line-height: 1;
        letter-spacing: -0.03em;
        background: linear-gradient(135deg, #ffffff, #00ff88);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        background-clip: text;
      }

      .tmgc-label {
        font-size: 10px;
        font-weight: 600;
        letter-spacing: 0.14em;
        text-transform: uppercase;
        color: rgba(136,136,136,.7);
      }

      .tmgc-btn-primary {
        background: linear-gradient(135deg, rgba(0,255,136,.2), rgba(0,255,136,.08));
        border: 1px solid rgba(0,255,136,.5);
        color: #00ff88;
        font-weight: 700;
        transition: all .25s ease;
        box-shadow: 0 0 20px rgba(0,255,136,.1);
      }
      .tmgc-btn-primary:hover {
        background: linear-gradient(135deg, rgba(0,255,136,.3), rgba(0,255,136,.15));
        box-shadow: 0 0 32px rgba(0,255,136,.2);
        transform: translateY(-1px);
      }

      .tmgc-status-pill {
        display: inline-flex;
        align-items: center;
        gap: 4px;
        padding: 3px 10px;
        border-radius: 999px;
        font-size: 10px;
        font-weight: 700;
        letter-spacing: 0.05em;
        text-transform: uppercase;
      }
      .tmgc-status-clean { background: rgba(0,255,136,.12); color: #00ff88; border: 1px solid rgba(0,255,136,.25); }
      .tmgc-status-suspicious { background: rgba(255,136,0,.12); color: #ff8800; border: 1px solid rgba(255,136,0,.25); }
      .tmgc-status-malicious { background: rgba(255,68,68,.12); color: #ff4444; border: 1px solid rgba(255,68,68,.25); }

      .tmgc-hero-gradient {
        background: radial-gradient(ellipse 80% 60% at 50% 40%, rgba(0,255,136,.06) 0%, transparent 70%);
      }

      @media (max-width: 640px) {
        .tmgc-stat { font-size: 24px; }
      }
    `}</style>
  );
}

export function StatCard({ icon, label, value, sub, trend }) {
  return (
    <div className="tmgc-card rounded-xl p-4">
      <div className="flex items-start justify-between">
        <div className="flex h-9 w-9 items-center justify-center rounded-lg border border-[#00ff88]/20 bg-[#00ff88]/5 text-[#00ff88]">
          {icon}
        </div>
        {trend && (
          <span className={`text-[10px] font-bold ${trend > 0 ? "text-[#ff4444]" : "text-[#00ff88]"}`}>
            {trend > 0 ? "↑" : "↓"} {Math.abs(trend)}%
          </span>
        )}
      </div>
      <p className="tmgc-stat mt-3">{value}</p>
      <p className="tmgc-label mt-1">{label}</p>
      {sub && <p className="mt-1 text-[10px] text-zinc-600">{sub}</p>}
    </div>
  );
}

export function RecentScanRow({ domain, status, time, score }) {
  const statusClass =
    status === "CLEAN" ? "tmgc-status-clean" :
    status === "SUSPICIOUS" ? "tmgc-status-suspicious" :
    "tmgc-status-malicious";

  return (
    <div className="flex items-center gap-3 rounded-lg border border-[#00ff88]/5 bg-black/20 px-3 py-2.5 transition hover:border-[#00ff88]/15">
      <span className={`tmgc-status-pill ${statusClass}`}>{status}</span>
      <span className="min-w-0 flex-1 truncate text-xs font-medium text-zinc-300">{domain}</span>
      <span className="text-[10px] font-bold text-zinc-500">{score}/100</span>
      <span className="text-[10px] text-zinc-600">{time}</span>
    </div>
  );
}
