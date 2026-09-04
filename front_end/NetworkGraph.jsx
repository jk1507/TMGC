import React, { useRef, useEffect, useState } from "react";

const DEFAULT_PLANETS = [
  { id: "ip", label: "No IP resolved", type: "ip" },
  { id: "registrar", label: "Registrar", type: "registrar" },
  { id: "ns", label: "NS Records", type: "dns" },
  { id: "ssl", label: "SSL Cert", type: "ssl" },
  { id: "mx", label: "MX Server", type: "mail" },
];

const TYPE_COLORS = {
  domain: "#00ff88",
  ip: "#4488ff",
  subdomain: "#00ccff",
  registrar: "#ff8800",
  dns: "#aa66ff",
  ssl: "#00ffaa",
  mail: "#ffaa44",
};

const TYPE_RGB = {
  domain: "0,255,136",
  ip: "68,136,255",
  subdomain: "0,204,255",
  registrar: "255,136,0",
  dns: "170,102,255",
  ssl: "0,255,170",
  mail: "255,170,68",
};

const TYPE_LABELS = {
  domain: "Target Domain",
  ip: "IP Address",
  subdomain: "Subdomain",
  registrar: "Registrar",
  dns: "Nameserver",
  ssl: "SSL Issuer",
  mail: "MX Server",
};

const PLANET_RADIUS = { ip: 8, subdomain: 7, registrar: 9, dns: 8, ssl: 8, mail: 8 };

// Starfield particles drifting with depth parallax
const PARTICLES = Array.from({ length: 80 }, (_, i) => ({
  nx: Math.random(),
  ny: Math.random(),
  z: Math.random() * 220 - 80,
  r: Math.random() * 1.2 + 0.3,
  speed: Math.random() * 0.02 + 0.004,
  phase: Math.random() * Math.PI * 2,
  color: i % 3 === 0 ? "0,255,136" : "120,220,255",
}));

function shade(hex, factor) {
  const num = parseInt(hex.slice(1), 16);
  const r = Math.round(((num >> 16) & 255) * factor);
  const g = Math.round(((num >> 8) & 255) * factor);
  const b = Math.round((num & 255) * factor);
  return `rgb(${r},${g},${b})`;
}

function truncate(label) {
  return label.length > 18 ? label.slice(0, 16) + "…" : label;
}

function cleanLabel(value) {
  return String(value).replace(/\.$/, "");
}

// Build the solar system from real scan data — each relationship is a planet
// that gets its own orbit ring around the domain sun.
function buildNodes(data, domain) {
  const dns = data ? data.dns_data || {} : {};
  const meta = data ? data.parsed_meta || {} : {};
  const planets = [];

  if (!data) {
    DEFAULT_PLANETS.forEach((n) => planets.push({ ...n }));
  } else {
    const seen = new Set();

    const primaryIp = data.ip_address || data.target_ip;
    if (primaryIp && primaryIp !== "N/A") {
      planets.push({ id: "ip", label: cleanLabel(primaryIp), type: "ip" });
      seen.add(String(primaryIp));
    }

    // Additional A records become their own planets (capped to keep it readable)
    (dns.a_records || []).forEach((rec, i) => {
      if (i >= 3) return;
      const r = String(rec);
      if (seen.has(r)) return;
      seen.add(r);
      planets.push({ id: `a${i}`, label: cleanLabel(r), type: "ip" });
    });

    const registrar = meta.registrar;
    if (registrar && registrar !== "N/A") {
      planets.push({ id: "registrar", label: cleanLabel(registrar), type: "registrar" });
    }

    const ns = (dns.nameservers && dns.nameservers[0]) || (data.nameservers && data.nameservers[0]);
    if (ns) {
      planets.push({ id: "ns", label: cleanLabel(ns), type: "dns" });
    }

    const ssl = meta.ssl_issuer || data.ssl_issuer;
    if (ssl && ssl !== "N/A") {
      planets.push({ id: "ssl", label: cleanLabel(ssl), type: "ssl" });
    }

    const mx = dns.mx_records && dns.mx_records[0];
    if (mx) {
      planets.push({ id: "mx", label: cleanLabel(mx), type: "mail" });
    }
  }

  // Cap so the outer orbit stays inside the canvas, then assign orbit parameters
  planets.slice(0, 6).forEach((n, i) => {
    n.orbitRadius = Math.min(150, 56 + i * 22);
    n.orbitPhase = (i / Math.max(1, planets.length)) * Math.PI * 2 + i * 0.6;
    n.orbitSpeed = 0.1 + (i % 3) * 0.045;
  });

  return {
    sunLabel: domain || data?.domain || "Target Domain",
    planets: planets.slice(0, 6),
  };
}

export default function NetworkGraph({ domain = "example.com", data, className = "" }) {
  const canvasRef = useRef(null);
  const rafRef = useRef(null);
  const frameCountRef = useRef(0);
  const autoRotRef = useRef(0);
  const userRotRef = useRef(0);
  const zoomRef = useRef(1);
  const viewCenterRef = useRef({ x: 0, y: 0 });
  const projectedRef = useRef([]);
  const hoverRef = useRef(null);
  const draggingRef = useRef(false);
  const dragStartRef = useRef(0);
  const dragLastRef = useRef(0);
  const clickMovedRef = useRef(false);
  const [selected, setSelected] = useState(null);
  const [hoverId, setHoverId] = useState(null);
  const [dragging, setDragging] = useState(false);
  const [zoomPct, setZoomPct] = useState(100);

  const { sunLabel, planets } = React.useMemo(() => buildNodes(data, domain), [data, domain]);
  const usedTypes = React.useMemo(
    () => new Set(["domain", ...planets.map((p) => p.type)]),
    [planets]
  );

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    const dpr = window.devicePixelRatio || 1;
    let w = canvas.offsetWidth;
    let h = canvas.offsetHeight;

    function sizeCanvas() {
      w = canvas.offsetWidth;
      h = canvas.offsetHeight;
      canvas.width = w * dpr;
      canvas.height = h * dpr;
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      viewCenterRef.current = { x: w / 2, y: h / 2 };
    }
    sizeCanvas();

    function project(x, y, z, rotY) {
      const cos = Math.cos(rotY);
      const sin = Math.sin(rotY);
      const xr = x * cos - z * sin;
      const zr = x * sin + z * cos;
      const scale = (400 * zoomRef.current) / (400 - zr);
      const c = viewCenterRef.current;
      return { x: c.x + xr * scale, y: c.y + y * scale, z: zr };
    }

    function handleWheel(e) {
      e.preventDefault();
      const rect = canvas.getBoundingClientRect();
      const qx = e.clientX - rect.left;
      const qy = e.clientY - rect.top;
      const factor = e.deltaY < 0 ? 1.12 : 0.88;
      const next = Math.min(2.6, Math.max(0.5, zoomRef.current * factor));
      const k = next / zoomRef.current;
      const c = viewCenterRef.current;
      // Keep the point under the cursor anchored while zooming
      viewCenterRef.current = { x: qx + (c.x - qx) * k, y: qy + (c.y - qy) * k };
      zoomRef.current = next;
      setZoomPct(Math.round(next * 100));
    }

    function draw() {
      frameCountRef.current += 1;
      const frame = frameCountRef.current;
      const rot = autoRotRef.current + userRotRef.current;
      autoRotRef.current += 0.0028;

      if (canvas.offsetWidth !== w || canvas.offsetHeight !== h) sizeCanvas();

      // Don't paint into a hidden/zero-size canvas (would render everything in a corner)
      if (w === 0 || h === 0) {
        rafRef.current = requestAnimationFrame(draw);
        return;
      }

      const c = viewCenterRef.current;
      ctx.clearRect(0, 0, w, h);

      // Deep-space background
      const bg = ctx.createLinearGradient(0, 0, 0, h);
      bg.addColorStop(0, "#05090b");
      bg.addColorStop(0.55, "#030707");
      bg.addColorStop(1, "#010202");
      ctx.fillStyle = bg;
      ctx.fillRect(0, 0, w, h);

      // Central ambient glow
      const bgGlow = ctx.createRadialGradient(c.x, c.y, 0, c.x, c.y, Math.min(w, h) * 0.55);
      bgGlow.addColorStop(0, "rgba(255,170,40,0.05)");
      bgGlow.addColorStop(0.55, "rgba(0,180,255,0.02)");
      bgGlow.addColorStop(1, "transparent");
      ctx.fillStyle = bgGlow;
      ctx.fillRect(0, 0, w, h);

      // Starfield with rotation parallax
      PARTICLES.forEach((p) => {
        const px = (p.nx - 0.5) * (w + 240);
        const py = (p.ny - 0.5) * (h + 240);
        const pr = project(px, py, p.z, rot);
        if (pr.z > 240) return;
        const twinkle = 0.35 + 0.65 * Math.abs(Math.sin(p.phase + frame * p.speed));
        ctx.globalAlpha = twinkle * 0.7;
        ctx.fillStyle = `rgb(${p.color})`;
        ctx.beginPath();
        ctx.arc(pr.x, pr.y, p.r, 0, Math.PI * 2);
        ctx.fill();
      });
      ctx.globalAlpha = 1;

      // The sun (domain) sits at the center
      const sunY = Math.sin(frame * 0.01) * 2;
      const sun = {
        id: "domain",
        type: "domain",
        label: sunLabel,
        r: 20,
        ...project(0, sunY, 0, rot),
      };

      // Planets orbit the sun on their own rings
      const projected = planets.map((p, i) => {
        const angle = p.orbitPhase + frame * 0.004 * p.orbitSpeed;
        const px = Math.cos(angle) * p.orbitRadius;
        const py = Math.sin(angle) * p.orbitRadius + Math.sin(frame * 0.012 + i * 1.7) * 2;
        return {
          ...p,
          r: PLANET_RADIUS[p.type] || 8,
          ...project(px, py, 0, rot),
        };
      });
      projectedRef.current = [sun, ...projected];

      const hovered = hoverRef.current;

      // Orbit rings (dashed paths the planets travel on)
      planets.forEach((p) => {
        ctx.beginPath();
        const steps = 48;
        for (let k = 0; k <= steps; k++) {
          const a = (k / steps) * Math.PI * 2;
          const pt = project(Math.cos(a) * p.orbitRadius, Math.sin(a) * p.orbitRadius, 0, rot);
          if (k === 0) ctx.moveTo(pt.x, pt.y);
          else ctx.lineTo(pt.x, pt.y);
        }
        ctx.setLineDash([2, 6]);
        ctx.lineWidth = 1;
        ctx.strokeStyle = `rgba(${TYPE_RGB[p.type]},${hovered && hovered !== p.id ? 0.05 : 0.16})`;
        ctx.stroke();
      });
      ctx.setLineDash([]);

      // Solar-wind beams from the sun to each planet
      projected.forEach((p) => {
        const toRgb = TYPE_RGB[p.type];
        const dim = hovered && hovered !== "domain" && p.id !== hovered;
        const a = dim ? 0.05 : 0.38;

        // Soft underglow beam
        ctx.beginPath();
        ctx.moveTo(sun.x, sun.y);
        ctx.lineTo(p.x, p.y);
        ctx.strokeStyle = `rgba(${toRgb},${a * 0.18})`;
        ctx.lineWidth = 3;
        ctx.stroke();

        // Animated dashed stream
        ctx.beginPath();
        ctx.moveTo(sun.x, sun.y);
        ctx.lineTo(p.x, p.y);
        const grad = ctx.createLinearGradient(sun.x, sun.y, p.x, p.y);
        grad.addColorStop(0, `rgba(255,190,80,${a})`);
        grad.addColorStop(1, `rgba(${toRgb},${a})`);
        ctx.strokeStyle = grad;
        ctx.lineWidth = 1;
        ctx.setLineDash([5, 13]);
        ctx.lineDashOffset = -frame * 1.4;
        ctx.stroke();
        ctx.setLineDash([]);

        // Energy pulse traveling along the beam
        const t = (frame * 0.006 + p.id.charCodeAt(0) * 0.07) % 1;
        const px = sun.x + (p.x - sun.x) * t;
        const py = sun.y + (p.y - sun.y) * t;
        const pgrad = ctx.createRadialGradient(px, py, 0, px, py, 4.5);
        pgrad.addColorStop(0, "rgba(255,255,255,0.85)");
        pgrad.addColorStop(0.4, `rgba(${toRgb},0.65)`);
        pgrad.addColorStop(1, "transparent");
        ctx.beginPath();
        ctx.arc(px, py, 4.5, 0, Math.PI * 2);
        ctx.fillStyle = pgrad;
        ctx.fill();
      });

      // Draw everything back-to-front by depth (planets can pass in front of the sun)
      [sun, ...projected]
        .slice()
        .sort((a, b) => a.z - b.z)
        .forEach((n) => {
          const isSun = n.type === "domain";
          const color = isSun ? "#ffb020" : TYPE_COLORS[n.type];
          const rgb = isSun ? "255,176,32" : TYPE_RGB[n.type];
          const isHover = hovered === n.id;
          const isDim =
            hovered && hovered !== n.id && !(isSun || hovered === "domain");
          const r = n.r * (isHover ? 1.35 : 1);
          const depthAlpha = 0.55 + (n.z + 200) / 400;
          const alpha = isDim ? depthAlpha * 0.22 : isHover ? 1 : isSun ? 1 : depthAlpha;

          if (isSun) {
            // Big soft corona
            const corona = ctx.createRadialGradient(n.x, n.y, r * 0.3, n.x, n.y, r * 4.2);
            corona.addColorStop(0, "rgba(255,190,80,0.5)");
            corona.addColorStop(0.45, "rgba(255,140,30,0.16)");
            corona.addColorStop(1, "transparent");
            ctx.beginPath();
            ctx.arc(n.x, n.y, r * 4.2, 0, Math.PI * 2);
            ctx.fillStyle = corona;
            ctx.fill();

            // Expanding pulse ring
            const pt = (frame * 0.016) % 1;
            ctx.beginPath();
            ctx.arc(n.x, n.y, r + 8 + pt * 26, 0, Math.PI * 2);
            ctx.globalAlpha = (1 - pt) * 0.4;
            ctx.strokeStyle = "rgba(0,255,136,0.8)";
            ctx.lineWidth = 1.4;
            ctx.stroke();
            ctx.globalAlpha = 1;

            // Chromosphere + core
            const body = ctx.createRadialGradient(
              n.x - r * 0.35,
              n.y - r * 0.4,
              r * 0.1,
              n.x,
              n.y,
              r * 1.05
            );
            body.addColorStop(0, "#fffbe8");
            body.addColorStop(0.35, "#ffd24a");
            body.addColorStop(0.75, "#ff8c1a");
            body.addColorStop(1, "#d84e05");
            ctx.beginPath();
            ctx.arc(n.x, n.y, r, 0, Math.PI * 2);
            ctx.fillStyle = body;
            ctx.shadowColor = "#ffb020";
            ctx.shadowBlur = isHover ? 34 : 22;
            ctx.fill();
            ctx.shadowBlur = 0;

            // Rim
            ctx.beginPath();
            ctx.arc(n.x, n.y, r, 0, Math.PI * 2);
            ctx.strokeStyle = isHover ? "rgba(255,220,140,0.95)" : "rgba(255,190,80,0.55)";
            ctx.lineWidth = isHover ? 2 : 1.2;
            ctx.stroke();

            // Rotating dashed ring around the sun
            ctx.save();
            ctx.translate(n.x, n.y);
            ctx.rotate(frame * 0.008);
            ctx.setLineDash([4, 8]);
            ctx.beginPath();
            ctx.arc(0, 0, r + 15, 0, Math.PI * 2);
            ctx.strokeStyle = "rgba(0,255,136,0.25)";
            ctx.lineWidth = 1;
            ctx.stroke();
            ctx.restore();
            ctx.setLineDash([]);
          } else {
            // Outer halo
            const halo = ctx.createRadialGradient(n.x, n.y, r * 0.2, n.x, n.y, r * 3);
            halo.addColorStop(0, `rgba(${rgb},${isHover ? 0.3 : 0.16})`);
            halo.addColorStop(1, "transparent");
            ctx.beginPath();
            ctx.arc(n.x, n.y, r * 3, 0, Math.PI * 2);
            ctx.fillStyle = halo;
            ctx.fill();

            // Expanding pulse ring
            if (!isDim) {
              const pt = (frame * 0.02 + n.x * 0.003 + n.y * 0.004) % 1;
              const pr = r + 4 + pt * 16;
              ctx.beginPath();
              ctx.arc(n.x, n.y, pr, 0, Math.PI * 2);
              ctx.globalAlpha = (1 - pt) * alpha * 0.5;
              ctx.strokeStyle = `rgba(${rgb},0.9)`;
              ctx.lineWidth = 1.2;
              ctx.stroke();
              ctx.globalAlpha = 1;
            }

            // Glassy body
            const body = ctx.createRadialGradient(
              n.x - r * 0.4,
              n.y - r * 0.45,
              r * 0.15,
              n.x,
              n.y,
              r * 1.05
            );
            body.addColorStop(0, "#ffffff");
            body.addColorStop(0.3, color);
            body.addColorStop(1, shade(color, 0.28));
            ctx.beginPath();
            ctx.arc(n.x, n.y, r, 0, Math.PI * 2);
            ctx.fillStyle = body;
            ctx.globalAlpha = alpha;
            ctx.shadowColor = color;
            ctx.shadowBlur = isHover ? 20 : 8;
            ctx.fill();
            ctx.shadowBlur = 0;
            ctx.globalAlpha = 1;

            // Rim
            ctx.beginPath();
            ctx.arc(n.x, n.y, r, 0, Math.PI * 2);
            ctx.strokeStyle = `rgba(${rgb},${isHover ? 0.95 : 0.55})`;
            ctx.lineWidth = isHover ? 2 : 1.1;
            ctx.stroke();
          }

          // Specular highlight
          ctx.beginPath();
          ctx.arc(n.x - r * 0.35, n.y - r * 0.4, r * 0.22, 0, Math.PI * 2);
          ctx.fillStyle = "rgba(255,255,255,0.75)";
          ctx.fill();

          // Label — sun below, planets flipped by hemisphere so they never crowd it
          const labelScale = Math.min(1.7, Math.max(0.85, zoomRef.current));
          ctx.font = `600 ${Math.round((isHover ? 11 : 9) * labelScale)}px Inter, system-ui`;
          ctx.textAlign = "center";
          ctx.fillStyle = isHover ? "#ffffff" : "#c9d4cf";
          ctx.shadowColor = color;
          ctx.shadowBlur = isHover ? 10 : 3;
          const labelAbove = !isSun && n.y < sun.y - 6;
          const labelY = labelAbove ? n.y - r - 7 : n.y + r + (isSun ? 20 : 15);
          ctx.fillText(truncate(n.label), n.x, labelY);
          ctx.shadowBlur = 0;
        });

      // Vignette for depth
      const vig = ctx.createRadialGradient(c.x, c.y, Math.min(w, h) * 0.35, c.x, c.y, Math.max(w, h) * 0.78);
      vig.addColorStop(0, "transparent");
      vig.addColorStop(1, "rgba(0,0,0,0.5)");
      ctx.fillStyle = vig;
      ctx.fillRect(0, 0, w, h);

      rafRef.current = requestAnimationFrame(draw);
    }

    draw();

    function onMove(e) {
      const rect = canvas.getBoundingClientRect();
      const x = e.clientX - rect.left;
      const y = e.clientY - rect.top;

      if (draggingRef.current) {
        userRotRef.current += (e.clientX - dragLastRef.current) * 0.006;
        dragLastRef.current = e.clientX;
        return;
      }

      let hit = null;
      let best = Infinity;
      projectedRef.current.forEach((n) => {
        const dist = Math.hypot(n.x - x, n.y - y);
        if (dist <= n.r + 10 && dist < best) {
          hit = n.id;
          best = dist;
        }
      });
      hoverRef.current = hit;
      setHoverId(hit);
    }

    function onUp(e) {
      if (draggingRef.current) {
        clickMovedRef.current = Math.abs(e.clientX - dragStartRef.current) > 5;
      }
      draggingRef.current = false;
      setDragging(false);
    }

    canvas.addEventListener("wheel", handleWheel, { passive: false });
    window.addEventListener("mousemove", onMove);
    window.addEventListener("mouseup", onUp);

    return () => {
      cancelAnimationFrame(rafRef.current);
      canvas.removeEventListener("wheel", handleWheel);
      window.removeEventListener("mousemove", onMove);
      window.removeEventListener("mouseup", onUp);
    };
  }, [planets, sunLabel]);

  const selectedNode =
    selected === "domain"
      ? { id: "domain", label: sunLabel, type: "domain" }
      : planets.find((p) => p.id === selected) || null;

  function handleCanvasClick(event) {
    if (clickMovedRef.current) {
      clickMovedRef.current = false;
      return;
    }
    const canvas = canvasRef.current;
    if (!canvas) return;
    const rect = canvas.getBoundingClientRect();
    const x = event.clientX - rect.left;
    const y = event.clientY - rect.top;
    let hit = null;
    let bestDist = Infinity;
    projectedRef.current.forEach((n) => {
      const dist = Math.hypot(n.x - x, n.y - y);
      if (dist <= n.r + 8 && dist < bestDist) {
        hit = n.id;
        bestDist = dist;
      }
    });
    setSelected((current) => (hit === current ? null : hit));
  }

  function handleMouseDown(event) {
    draggingRef.current = true;
    dragStartRef.current = event.clientX;
    dragLastRef.current = event.clientX;
    setDragging(true);
  }

  function handleDoubleClick() {
    zoomRef.current = 1;
    viewCenterRef.current = {
      x: canvasRef.current.offsetWidth / 2,
      y: canvasRef.current.offsetHeight / 2,
    };
    setZoomPct(100);
  }

  return (
    <div className={`relative flex flex-col ${className}`}>
      <div className="relative">
        <canvas
          ref={canvasRef}
          className="h-[360px] w-full rounded-xl"
          onClick={handleCanvasClick}
          onMouseDown={handleMouseDown}
          onDoubleClick={handleDoubleClick}
          onMouseLeave={() => {
            hoverRef.current = null;
            setHoverId(null);
          }}
          style={{ cursor: dragging ? "grabbing" : hoverId ? "pointer" : "grab" }}
        />
        {zoomPct !== 100 && (
          <div className="pointer-events-none absolute left-3 top-3 rounded-md border border-[#00ff88]/20 bg-black/60 px-1.5 py-0.5 font-mono text-[9px] text-[#00ff88]/80 backdrop-blur-sm">
            {zoomPct}%
          </div>
        )}
        <div className="pointer-events-none absolute bottom-2 left-3 text-[9px] font-medium tracking-wide text-zinc-600">
          drag to rotate · scroll to zoom · double-click to reset
        </div>
        {selectedNode && (
          <div className="absolute right-3 top-3 w-48 overflow-hidden rounded-lg border border-[#00ff88]/25 bg-[#060909]/95 shadow-[0_0_24px_rgba(0,255,136,0.12)] backdrop-blur-sm">
            <div className="flex items-center justify-between border-b border-[#00ff88]/10 px-3 py-1.5">
              <p className="text-[8px] font-bold tracking-[0.2em] text-[#00ff88]/70 uppercase">Node</p>
              <span
                className="h-1.5 w-1.5 rounded-full"
                style={{
                  backgroundColor: TYPE_COLORS[selectedNode.type],
                  boxShadow: `0 0 8px ${TYPE_COLORS[selectedNode.type]}`,
                }}
              />
            </div>
            <div className="px-3 py-2">
              <p className="font-mono truncate text-xs font-semibold text-white">{selectedNode.label}</p>
              <p
                className="mt-0.5 text-[9px] font-bold tracking-wider uppercase"
                style={{ color: TYPE_COLORS[selectedNode.type] }}
              >
                {TYPE_LABELS[selectedNode.type] || selectedNode.type}
              </p>
            </div>
          </div>
        )}
      </div>
      <div className="mt-2 flex flex-wrap gap-x-3 gap-y-1">
        {Object.entries(TYPE_COLORS)
          .filter(([type]) => usedTypes.has(type))
          .map(([type, color]) => (
            <span key={type} className="flex items-center gap-1.5 text-[9px] text-zinc-500">
              <span className="h-2 w-2 rounded-full" style={{ backgroundColor: color, boxShadow: `0 0 6px ${color}` }} />
              {TYPE_LABELS[type] || type}
            </span>
          ))}
      </div>
    </div>
  );
}