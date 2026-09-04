import React, { useRef, useEffect, useState, useCallback } from "react";
import {
  getLandPoints,
  latLonToUnit,
  rotateY,
  project,
  setupCanvas,
  drawEarthBase,
  drawEarthGrid,
  drawEarthLand,
  drawCityLights,
  drawThreatMarkers,
  THREAT_HOTSPOTS,
  drawGlobeBase,
  drawLatLonGrid,
  drawLandMasses,
  drawNetworkArcs,
  drawScanSweep,
  drawSpaceParticles,
  drawThreatHotspots,
} from "./globeUtils.js";
import { GLOBAL_THREAT_FALLBACK } from "./globalThreatFallback.js";

const API_URL = "/api/v1/global-threat-map";
const REFRESH_MS = 5 * 60 * 1000;

const TYPE_META = {
  banking: { label: "Banking & Finance", color: "#ff3b30" },
  email_cloud: { label: "Email & Cloud", color: "#ff6b35" },
  social: { label: "Social Media", color: "#ff9500" },
  delivery: { label: "Delivery & Shipping", color: "#ffd60a" },
  ecommerce: { label: "E-commerce & Retail", color: "#ffcc00" },
  crypto: { label: "Crypto & Wallets", color: "#ff2d55" },
  telecom: { label: "Telecom & ISPs", color: "#ff5e3a" },
  government: { label: "Government & Tax", color: "#ff453a" },
  gaming_media: { label: "Gaming & Streaming", color: "#ff7eb6" },
  other: { label: "Other / Generic", color: "#ff8a65" },
};

function typeColor(type) {
  return TYPE_META[type]?.color || "#ff453a";
}

function flagEmoji(code) {
  if (!code || code.length !== 2) return "🌐";
  return String.fromCodePoint(
    ...[...code.toUpperCase()].map((ch) => 0x1f1e6 + ch.charCodeAt(0) - 65)
  );
}

function timeAgo(date) {
  if (!date) return "";
  const seconds = Math.max(0, Math.round((Date.now() - date.getTime()) / 1000));
  if (seconds < 60) return `${seconds}s ago`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
  return `${Math.floor(seconds / 86400)}d ago`;
}

/* Classic animated globe — the original hero renderer (no live data, no markers). */
function ClassicGlobe({ className = "" }) {
  const canvasRef = useRef(null);
  const frameRef = useRef(null);
  const rotRef = useRef(0.6);
  const landRef = useRef(getLandPoints(2.2));

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    let t = 0;

    function draw() {
      const { ctx, cx, cy, radius, w, h } = setupCanvas(canvas);
      t += 0.016;
      rotRef.current += 0.0035;
      const rot = rotRef.current;

      ctx.clearRect(0, 0, w, h);

      const ambient = ctx.createRadialGradient(cx, cy, 0, cx, cy, radius * 1.5);
      ambient.addColorStop(0, "rgba(0,255,136,0.05)");
      ambient.addColorStop(1, "transparent");
      ctx.fillStyle = ambient;
      ctx.fillRect(0, 0, w, h);

      drawSpaceParticles(ctx, w, h, t);
      drawGlobeBase(ctx, cx, cy, radius);
      drawLatLonGrid(ctx, cx, cy, radius, rot, 8, 12);
      drawLandMasses(ctx, landRef.current, cx, cy, radius, rot);
      drawNetworkArcs(ctx, cx, cy, radius, rot, t);
      drawScanSweep(ctx, cx, cy, radius, t);
      drawThreatHotspots(ctx, THREAT_HOTSPOTS, cx, cy, radius, rot, t);

      frameRef.current = requestAnimationFrame(draw);
    }

    draw();
    const onResize = () => draw();
    window.addEventListener("resize", onResize);
    return () => {
      cancelAnimationFrame(frameRef.current);
      window.removeEventListener("resize", onResize);
    };
  }, []);

  return (
    <div className={className}>
      <canvas ref={canvasRef} className="h-[220px] w-full rounded-xl" />
      <p className="mt-2 text-center text-[9px] tracking-wider text-zinc-600 uppercase">Live Global Threat Activity</p>
    </div>
  );
}

export default function GlobalThreatMap({ className = "", compact = false, variant = "live" }) {
  if (variant === "classic") {
    return <ClassicGlobe className={className} />;
  }

  const canvasRef = useRef(null);
  const wrapRef = useRef(null);
  const tooltipRef = useRef(null);
  const rafRef = useRef(null);
  const rotRef = useRef(0.6);
  const userRotRef = useRef(0);
  const landRef = useRef(getLandPoints(2.0));
  const projectedRef = useRef([]);
  const hoverRef = useRef(null);
  const draggingRef = useRef(false);
  const dragLastRef = useRef(0);
  const clickMovedRef = useRef(false);
  const dataRef = useRef(GLOBAL_THREAT_FALLBACK);
  const [snapshot, setSnapshot] = useState(null);
  const [status, setStatus] = useState("loading");
  const [updatedAt, setUpdatedAt] = useState(null);
  const [hovered, setHovered] = useState(null);
  const [selected, setSelected] = useState(null);

  const load = useCallback(async () => {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 8000);
    try {
      const res = await fetch(API_URL, { cache: "no-store", signal: controller.signal });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const json = await res.json();
      if (!json || !Array.isArray(json.countries)) throw new Error("bad payload");
      dataRef.current = json;
      setSnapshot(json);
      setStatus(json.geocoded === false ? "degraded" : "live");
      setUpdatedAt(new Date());
    } catch (err) {
      dataRef.current = GLOBAL_THREAT_FALLBACK;
      setSnapshot(GLOBAL_THREAT_FALLBACK);
      setStatus("offline");
      setUpdatedAt(null);
    } finally {
      clearTimeout(timer);
    }
  }, []);

  useEffect(() => {
    load();
    const id = setInterval(load, REFRESH_MS);
    return () => clearInterval(id);
  }, [load]);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    let t = 0;

    function draw() {
      const { ctx, cx, cy, radius, w, h } = setupCanvas(canvas);
      t += 0.016;
      rotRef.current += 0.0035;
      const rot = rotRef.current + userRotRef.current;

      ctx.clearRect(0, 0, w, h);

      // Deep-space backdrop
      const bg = ctx.createLinearGradient(0, 0, 0, h);
      bg.addColorStop(0, "#04070f");
      bg.addColorStop(0.55, "#020408");
      bg.addColorStop(1, "#010203");
      ctx.fillStyle = bg;
      ctx.fillRect(0, 0, w, h);

      drawEarthBase(ctx, cx, cy, radius);
      drawEarthGrid(ctx, cx, cy, radius, rot);
      drawEarthLand(ctx, landRef.current, cx, cy, radius, rot);
      drawCityLights(ctx, landRef.current, cx, cy, radius, rot, t);

      // Project live attack hotspots
      const snap = dataRef.current;
      const markers = [];
      if (snap && Array.isArray(snap.countries)) {
        snap.countries.forEach((c) => {
          const unit = latLonToUnit(c.lat, c.lon);
          const r3 = rotateY(unit.x, unit.y, unit.z, rot);
          const p = project(r3.x, r3.y, r3.z, cx, cy, radius);
          const dominant = c.types?.[0]?.type || "other";
          markers.push({
            ...c,
            x: p.x,
            y: p.y,
            z: r3.z,
            typeColor: typeColor(dominant),
            dominant,
          });
        });
      }
      projectedRef.current = markers;
      drawThreatMarkers(ctx, markers, t);

      // Country labels for the top hotspots + hovered/selected
      const top = [...markers]
        .filter((m) => m.z > 0.03)
        .sort((a, b) => b.count - a.count)
        .slice(0, 8)
        .map((m) => m.code);
      const extra = [hoverRef.current, selected].filter(
        (c) => c && !top.includes(c) && markers.some((m) => m.code === c)
      );
      const labeled = new Set([...top, ...extra]);
      markers.forEach((m) => {
        if (!labeled.has(m.code) || m.z < 0.03) return;
        ctx.font = "600 9px Inter, system-ui";
        ctx.textAlign = "center";
        ctx.fillStyle = "rgba(255,235,230,0.85)";
        ctx.shadowColor = "rgba(0,0,0,0.9)";
        ctx.shadowBlur = 4;
        ctx.fillText(m.name.length > 14 ? m.name.slice(0, 12) + "…" : m.name, m.x, m.y - 12);
        ctx.shadowBlur = 0;
      });

      // Keep the tooltip glued to its marker
      const tooltip = tooltipRef.current;
      if (tooltip) {
        const code = hoverRef.current || selected;
        const m = markers.find((mk) => mk.code === code);
        if (m && m.z > 0.03) {
          const wrap = wrapRef.current;
          const rect = wrap.getBoundingClientRect();
          const left = Math.min(Math.max(m.x - 92, 8), rect.width - 200);
          const top = m.y - 130 > 8 ? m.y - 130 : m.y + 16;
          tooltip.style.left = `${left}px`;
          tooltip.style.top = `${top}px`;
          tooltip.style.opacity = "1";
        } else {
          tooltip.style.opacity = "0";
        }
      }

      rafRef.current = requestAnimationFrame(draw);
    }

    draw();
    const onResize = () => draw();
    window.addEventListener("resize", onResize);
    return () => {
      cancelAnimationFrame(rafRef.current);
      window.removeEventListener("resize", onResize);
    };
  }, [selected]);

  function handleMove(event) {
    const canvas = canvasRef.current;
    if (!canvas) return;
    if (draggingRef.current) {
      userRotRef.current += (event.clientX - dragLastRef.current) * 0.006;
      dragLastRef.current = event.clientX;
      return;
    }
    const rect = canvas.getBoundingClientRect();
    const x = event.clientX - rect.left;
    const y = event.clientY - rect.top;
    let hit = null;
    let best = Infinity;
    projectedRef.current.forEach((m) => {
      const size = Math.min(15, 3.5 + Math.sqrt(m.count) * 2.2);
      const dist = Math.hypot(m.x - x, m.y - y);
      if (dist <= size + 10 && dist < best) {
        hit = m.code;
        best = dist;
      }
    });
    hoverRef.current = hit;
    setHovered(hit);
  }

  function handleDown(event) {
    draggingRef.current = true;
    dragLastRef.current = event.clientX;
  }

  function handleUp(event) {
    if (draggingRef.current) {
      clickMovedRef.current = Math.abs(event.clientX - dragLastRef.current) > 6;
    }
    draggingRef.current = false;
  }

  function handleClick() {
    if (clickMovedRef.current) {
      clickMovedRef.current = false;
      return;
    }
    setSelected((current) => (current === hoverRef.current ? null : hoverRef.current));
  }

  const tooltipCountry =
    snapshot?.countries.find((c) => c.code === (hovered || selected)) || null;
  const statusMeta = {
    live: { dot: "bg-[#00ff88]", text: "LIVE", cls: "text-[#00ff88]" },
    degraded: { dot: "bg-yellow-400", text: "DEGRADED", cls: "text-yellow-300" },
    offline: { dot: "bg-red-500", text: "OFFLINE", cls: "text-red-400" },
    loading: { dot: "bg-amber-400 animate-pulse", text: "CONNECTING", cls: "text-amber-300" },
  }[status];

  const total = snapshot?.total_attacks ?? GLOBAL_THREAT_FALLBACK.total_attacks;
  const countryCount = snapshot?.countries?.length ?? GLOBAL_THREAT_FALLBACK.countries.length;
  const types = snapshot?.types ?? GLOBAL_THREAT_FALLBACK.types;
  const shownTypes = types.slice(0, 6);

  return (
    <div ref={wrapRef} className={`relative ${className}`}>
      <canvas
        ref={canvasRef}
        className={`w-full rounded-xl ${compact ? "h-[300px]" : "h-[320px]"}`}
        onMouseMove={handleMove}
        onMouseDown={handleDown}
        onMouseUp={handleUp}
        onMouseLeave={() => {
          hoverRef.current = null;
          setHovered(null);
        }}
        onClick={handleClick}
        style={{ cursor: draggingRef.current ? "grabbing" : hovered ? "pointer" : "grab" }}
      />

      {/* Status bar */}
      <div className="pointer-events-none absolute left-2 top-2 flex items-center gap-2">
        <span className="flex items-center gap-1.5 rounded-md border border-white/10 bg-black/60 px-2 py-1 backdrop-blur-sm">
          <span className={`h-1.5 w-1.5 rounded-full ${statusMeta.dot}`} />
          <span className={`text-[9px] font-bold tracking-wider ${statusMeta.cls}`}>{statusMeta.text}</span>
        </span>
        {!compact && (
          <span className="rounded-md border border-white/10 bg-black/60 px-2 py-1 font-mono text-[9px] text-zinc-400 backdrop-blur-sm">
            {total.toLocaleString()} attacks · {countryCount} countries
          </span>
        )}
        {updatedAt && (
          <span className="rounded-md border border-white/10 bg-black/60 px-2 py-1 font-mono text-[9px] text-zinc-500 backdrop-blur-sm">
            {timeAgo(updatedAt)}
          </span>
        )}
      </div>

      {/* Marker tooltip */}
      {tooltipCountry && (
        <div
          ref={tooltipRef}
          className="pointer-events-none absolute w-44 rounded-lg border border-red-500/30 bg-[#0a0608]/95 p-3 opacity-0 shadow-[0_0_28px_rgba(255,45,40,0.18)] backdrop-blur-sm transition-opacity duration-150"
        >
          <div className="flex items-center justify-between">
            <p className="text-[8px] font-bold tracking-[0.2em] text-red-400/70 uppercase">Hotspot</p>
            <span className="text-sm">{flagEmoji(tooltipCountry.code)}</span>
          </div>
          <p className="mt-1 truncate text-xs font-bold text-white">{tooltipCountry.name}</p>
          <p className="mt-0.5 text-[10px] text-red-300">
            {tooltipCountry.count.toLocaleString()} active phishing attacks
          </p>
          {tooltipCountry.types?.slice(0, 3).map((t) => (
            <div key={t.type} className="mt-1 flex items-center justify-between text-[10px]">
              <span className="flex items-center gap-1.5 text-zinc-400">
                <span
                  className="h-1.5 w-1.5 rounded-full"
                  style={{ backgroundColor: typeColor(t.type), boxShadow: `0 0 5px ${typeColor(t.type)}` }}
                />
                {t.label}
              </span>
              <span className="font-mono text-zinc-300">{t.count}</span>
            </div>
          ))}
          <p className="mt-2 border-t border-white/5 pt-1.5 text-[8px] tracking-wide text-zinc-600 uppercase">
            PhishTank · verified online
          </p>
        </div>
      )}

      {/* Attack-type legend */}
      {!compact && (
        <div className="mt-2 flex flex-wrap items-center gap-x-3 gap-y-1">
          {shownTypes.map((t) => (
            <span key={t.type} className="flex items-center gap-1.5 text-[9px] text-zinc-500">
              <span
                className="h-2 w-2 rounded-full"
                style={{ backgroundColor: typeColor(t.type), boxShadow: `0 0 6px ${typeColor(t.type)}` }}
              />
              {t.label}
              <span className="font-mono text-zinc-600">{t.count}</span>
            </span>
          ))}
          {types.length > shownTypes.length && (
            <span className="text-[9px] text-zinc-600">+{types.length - shownTypes.length} more</span>
          )}
        </div>
      )}
    </div>
  );
}