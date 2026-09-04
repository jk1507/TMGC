import React, { useRef, useEffect } from "react";

const SERIES = [
  { name: "Phishing", color: "#ff4444", data: [12, 18, 15, 22, 28, 24, 32, 29, 35, 31, 38, 42] },
  { name: "Malware", color: "#ff8800", data: [8, 10, 14, 11, 16, 19, 15, 22, 18, 25, 21, 28] },
  { name: "Clean", color: "#00ff88", data: [45, 42, 48, 44, 40, 46, 43, 47, 41, 45, 48, 44] },
  { name: "Suspicious", color: "#ffaa00", data: [5, 8, 6, 10, 12, 9, 14, 11, 15, 13, 16, 18] },
];

export default function ThreatTrendChart({ className = "" }) {
  const canvasRef = useRef(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    const w = canvas.offsetWidth;
    const h = canvas.offsetHeight;
    const dpr = window.devicePixelRatio || 1;
    canvas.width = w * dpr;
    canvas.height = h * dpr;
    ctx.scale(dpr, dpr);

    const pad = { top: 20, right: 16, bottom: 28, left: 36 };
    const chartW = w - pad.left - pad.right;
    const chartH = h - pad.top - pad.bottom;
    const maxVal = 55;

    ctx.clearRect(0, 0, w, h);

    for (let i = 0; i <= 4; i++) {
      const y = pad.top + (chartH / 4) * i;
      ctx.beginPath();
      ctx.moveTo(pad.left, y);
      ctx.lineTo(w - pad.right, y);
      ctx.strokeStyle = "rgba(0,255,136,0.06)";
      ctx.lineWidth = 1;
      ctx.stroke();
      ctx.font = "9px Inter, system-ui";
      ctx.fillStyle = "rgba(150,150,150,0.4)";
      ctx.textAlign = "right";
      ctx.fillText(String(Math.round(maxVal - (maxVal / 4) * i)), pad.left - 6, y + 3);
    }

    const months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
    months.forEach((m, i) => {
      if (i % 2 !== 0) return;
      const x = pad.left + (chartW / 11) * i;
      ctx.font = "9px Inter, system-ui";
      ctx.fillStyle = "rgba(150,150,150,0.35)";
      ctx.textAlign = "center";
      ctx.fillText(m, x, h - 8);
    });

    SERIES.forEach((series) => {
      ctx.beginPath();
      series.data.forEach((val, i) => {
        const x = pad.left + (chartW / (series.data.length - 1)) * i;
        const y = pad.top + chartH - (val / maxVal) * chartH;
        if (i === 0) ctx.moveTo(x, y);
        else ctx.lineTo(x, y);
      });
      ctx.strokeStyle = series.color;
      ctx.lineWidth = 2;
      ctx.shadowColor = series.color;
      ctx.shadowBlur = 6;
      ctx.stroke();
      ctx.shadowBlur = 0;

      const last = series.data.length - 1;
      const lx = pad.left + chartW;
      const ly = pad.top + chartH - (series.data[last] / maxVal) * chartH;
      ctx.beginPath();
      ctx.arc(lx, ly, 3, 0, Math.PI * 2);
      ctx.fillStyle = series.color;
      ctx.fill();
    });
  }, []);

  return (
    <div className={className}>
      <canvas ref={canvasRef} className="h-[180px] w-full" />
      <div className="mt-2 flex flex-wrap gap-3">
        {SERIES.map((s) => (
          <span key={s.name} className="flex items-center gap-1.5 text-[10px] text-zinc-400">
            <span className="h-1.5 w-4 rounded-full" style={{ backgroundColor: s.color }} />
            {s.name}
          </span>
        ))}
      </div>
    </div>
  );
}
