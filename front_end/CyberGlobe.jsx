import React, { useRef, useEffect } from "react";
import {
  drawGlobeBase,
  drawLandMasses,
  drawLatLonGrid,
  getLandPoints,
} from "./globeUtils.js";

const THREAT_LABELS = [
  { text: "Phishing", angle: 0.4, dist: 1.42, color: "#ff4444" },
  { text: "Malware", angle: 1.9, dist: 1.48, color: "#ff8800" },
  { text: "Clean", angle: 3.6, dist: 1.38, color: "#00ff88" },
  { text: "Suspicious", angle: 5.1, dist: 1.44, color: "#ffaa00" },
  { text: "Spam", angle: 6.7, dist: 1.4, color: "#4488ff" },
];

export default function CyberGlobe({ size = 420, className = "" }) {
  const canvasRef = useRef(null);
  const frameRef = useRef(null);
  const rotRef = useRef(0.4);
  const landRef = useRef(getLandPoints(2));

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    canvas.style.width = `${size}px`;
    canvas.style.height = `${size}px`;

    let t = 0;

    function draw() {
      const dpr = window.devicePixelRatio || 1;
      canvas.width = size * dpr;
      canvas.height = size * dpr;
      const ctx = canvas.getContext("2d");
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);

      t += 0.016;
      rotRef.current += 0.004;
      const rot = rotRef.current;
      const cx = size / 2;
      const cy = size / 2;
      const radius = size * 0.34;

      ctx.clearRect(0, 0, size, size);

      const glow = ctx.createRadialGradient(cx, cy, radius * 0.2, cx, cy, radius * 1.7);
      glow.addColorStop(0, "rgba(0,255,136,0.1)");
      glow.addColorStop(0.5, "rgba(0,255,136,0.04)");
      glow.addColorStop(1, "transparent");
      ctx.fillStyle = glow;
      ctx.fillRect(0, 0, size, size);

      drawGlobeBase(ctx, cx, cy, radius);
      drawLatLonGrid(ctx, cx, cy, radius, rot, 10, 16);
      drawLandMasses(ctx, landRef.current, cx, cy, radius, rot);

      THREAT_LABELS.forEach((label) => {
        const a = label.angle + rot * 0.25;
        const lx = cx + Math.cos(a) * radius * label.dist;
        const ly = cy + Math.sin(a) * radius * label.dist * 0.72;
        const pulse = 0.65 + Math.sin(t * 2 + label.angle) * 0.35;

        const edgeX = cx + Math.cos(a) * radius * 0.92;
        const edgeY = cy + Math.sin(a) * radius * 0.68;
        ctx.beginPath();
        ctx.moveTo(edgeX, edgeY);
        ctx.lineTo(lx, ly);
        ctx.strokeStyle = `${label.color}${Math.round(pulse * 70).toString(16).padStart(2, "0")}`;
        ctx.lineWidth = 1;
        ctx.stroke();

        ctx.beginPath();
        ctx.arc(lx, ly, 3.5, 0, Math.PI * 2);
        ctx.fillStyle = label.color;
        ctx.shadowColor = label.color;
        ctx.shadowBlur = 14;
        ctx.fill();
        ctx.shadowBlur = 0;

        ctx.font = "600 11px Inter, system-ui, sans-serif";
        ctx.fillStyle = label.color;
        ctx.textAlign = lx > cx ? "left" : "right";
        ctx.fillText(label.text, lx + (lx > cx ? 10 : -10), ly + 4);
      });

      frameRef.current = requestAnimationFrame(draw);
    }

    draw();
    return () => cancelAnimationFrame(frameRef.current);
  }, [size]);

  return (
    <div className={`relative ${className}`} style={{ width: size, height: size }}>
      <canvas ref={canvasRef} className="block" />
      <div
        className="pointer-events-none absolute inset-0 rounded-full"
        style={{ boxShadow: "inset 0 0 90px rgba(0,255,136,0.07), 0 0 70px rgba(0,255,136,0.1)" }}
      />
    </div>
  );
}
