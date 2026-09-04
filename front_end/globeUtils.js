/** Shared 3D globe math + land mask for canvas renderers */

export const THREAT_HOTSPOTS = [
  { lat: 40.7, lon: -74.0, intensity: 0.92, label: "US-East" },
  { lat: 37.8, lon: -122.4, intensity: 0.74, label: "US-West" },
  { lat: 51.5, lon: -0.1, intensity: 0.88, label: "EU" },
  { lat: 25.2, lon: 55.3, intensity: 0.65, label: "ME" },
  { lat: 35.7, lon: 139.7, intensity: 0.95, label: "Asia" },
  { lat: 1.3, lon: 103.8, intensity: 0.78, label: "SE-Asia" },
  { lat: -23.5, lon: -46.6, intensity: 0.52, label: "SA" },
  { lat: -1.3, lon: 36.8, intensity: 0.62, label: "Africa" },
  { lat: -33.9, lon: 151.2, intensity: 0.48, label: "Oceania" },
];

export function latLonToUnit(lat, lon) {
  const phi = ((90 - lat) * Math.PI) / 180;
  const theta = ((lon + 180) * Math.PI) / 180;
  return {
    x: -Math.sin(phi) * Math.cos(theta),
    y: Math.cos(phi),
    z: Math.sin(phi) * Math.sin(theta),
  };
}

function softBlob(lat, lon, centerLat, centerLon, radiusLat, radiusLon) {
  const dx = (lon - centerLon) / radiusLon;
  const dy = (lat - centerLat) / radiusLat;
  return dx * dx + dy * dy <= 1;
}

function isLand(lat, lon) {
  const continents = [
    [49, -103, 31, 57], [18, -99, 15, 22], [61, -42, 11, 20],
    [-14, -60, 39, 25], [-36, -68, 16, 11],
    [52, 15, 20, 34], [19, 20, 39, 28], [-23, 24, 16, 18],
    [51, 79, 26, 59], [24, 78, 21, 29], [11, 103, 12, 23],
    [36, 138, 10, 9], [-25, 134, 17, 24], [-42, 172, 6, 7],
    [67, 88, 10, 42], [65, -19, 4, 6],
  ];
  const onBlob = continents.some(([cLat, cLon, rLat, rLon]) => softBlob(lat, lon, cLat, cLon, rLat, rLon));
  if (!onBlob) return false;

  const coastNoise =
    Math.sin((lat + lon) * 0.19) * 0.55 +
    Math.sin(lat * 0.41) * 0.28 +
    Math.cos(lon * 0.31) * 0.33;
  return coastNoise > -0.78;
}

let landCache = null;
export function getLandPoints(step = 2.5) {
  if (landCache && landCache.step === step) return landCache.points;
  const points = [];
  for (let lat = -58; lat <= 74; lat += step) {
    for (let lon = -180; lon < 180; lon += step) {
      if (isLand(lat, lon)) points.push(latLonToUnit(lat, lon));
    }
  }
  landCache = { step, points };
  return points;
}

export function rotateY(x, y, z, rot) {
  const cos = Math.cos(rot);
  const sin = Math.sin(rot);
  return {
    x: x * cos + z * sin,
    y,
    z: -x * sin + z * cos,
  };
}

export function project(x, y, z, cx, cy, radius) {
  const depth = 2.15 - z * 0.52;
  const scale = 1 / depth;
  return { x: cx + x * radius * scale, y: cy + y * radius * scale, z, scale };
}

export function setupCanvas(canvas, dpr = window.devicePixelRatio || 1) {
  const w = canvas.offsetWidth;
  const h = canvas.offsetHeight;
  canvas.width = Math.max(1, Math.floor(w * dpr));
  canvas.height = Math.max(1, Math.floor(h * dpr));
  const ctx = canvas.getContext("2d");
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  return { ctx, w, h, cx: w / 2, cy: h / 2, radius: Math.min(w, h) * 0.42 };
}

export function drawGlobeBase(ctx, cx, cy, radius) {
  const outerGlow = ctx.createRadialGradient(cx, cy, radius * 0.8, cx, cy, radius * 1.75);
  outerGlow.addColorStop(0, "rgba(0,255,175,0.22)");
  outerGlow.addColorStop(0.45, "rgba(0,255,175,0.08)");
  outerGlow.addColorStop(1, "transparent");
  ctx.beginPath();
  ctx.arc(cx, cy, radius * 1.72, 0, Math.PI * 2);
  ctx.fillStyle = outerGlow;
  ctx.fill();

  const body = ctx.createRadialGradient(cx - radius * 0.38, cy - radius * 0.35, radius * 0.06, cx, cy, radius * 1.08);
  body.addColorStop(0, "rgba(45,255,195,0.42)");
  body.addColorStop(0.28, "rgba(0,145,105,0.45)");
  body.addColorStop(0.62, "rgba(0,42,34,0.94)");
  body.addColorStop(1, "rgba(0,4,6,0.98)");
  ctx.beginPath();
  ctx.arc(cx, cy, radius, 0, Math.PI * 2);
  ctx.fillStyle = body;
  ctx.fill();

  const shade = ctx.createRadialGradient(cx + radius * 0.42, cy + radius * 0.08, radius * 0.12, cx + radius * 0.42, cy + radius * 0.08, radius * 1.05);
  shade.addColorStop(0, "transparent");
  shade.addColorStop(0.5, "rgba(0,0,0,0.18)");
  shade.addColorStop(1, "rgba(0,0,0,0.62)");
  ctx.beginPath();
  ctx.arc(cx, cy, radius, 0, Math.PI * 2);
  ctx.fillStyle = shade;
  ctx.fill();

  ctx.beginPath();
  ctx.arc(cx, cy, radius, 0, Math.PI * 2);
  ctx.strokeStyle = "rgba(80,255,205,0.62)";
  ctx.lineWidth = 1.6;
  ctx.stroke();

  ctx.beginPath();
  ctx.arc(cx - radius * 0.16, cy - radius * 0.18, radius * 0.72, Math.PI * 1.15, Math.PI * 1.95);
  ctx.strokeStyle = "rgba(160,255,225,0.28)";
  ctx.lineWidth = 2;
  ctx.stroke();
}

export function drawSpaceParticles(ctx, w, h, t) {
  for (let i = 0; i < 54; i++) {
    const x = (Math.sin(i * 91.7) * 0.5 + 0.5) * w;
    const y = (Math.cos(i * 43.3) * 0.5 + 0.5) * h;
    const pulse = 0.35 + Math.sin(t * 1.6 + i) * 0.25;
    ctx.beginPath();
    ctx.arc(x, y, i % 7 === 0 ? 1.7 : 0.8, 0, Math.PI * 2);
    ctx.fillStyle = `rgba(0,255,180,${Math.max(0.08, pulse)})`;
    ctx.fill();
  }
}

export function drawNetworkArcs(ctx, cx, cy, radius, rot, t) {
  const pairs = [[0, 2], [1, 4], [2, 5], [3, 6], [4, 7], [5, 8]];
  pairs.forEach(([a, b], i) => {
    const from = THREAT_HOTSPOTS[a];
    const to = THREAT_HOTSPOTS[b];
    const p1u = rotateY(...Object.values(latLonToUnit(from.lat, from.lon)), rot);
    const p2u = rotateY(...Object.values(latLonToUnit(to.lat, to.lon)), rot);
    if (p1u.z < -0.1 && p2u.z < -0.1) return;
    const p1 = project(p1u.x, p1u.y, p1u.z, cx, cy, radius);
    const p2 = project(p2u.x, p2u.y, p2u.z, cx, cy, radius);
    const mx = (p1.x + p2.x) / 2 + Math.sin(t + i) * 14;
    const my = (p1.y + p2.y) / 2 - radius * (0.25 + (i % 3) * 0.07);
    ctx.beginPath();
    ctx.moveTo(p1.x, p1.y);
    ctx.quadraticCurveTo(mx, my, p2.x, p2.y);
    ctx.strokeStyle = i % 2 ? "rgba(0,190,255,0.18)" : "rgba(0,255,170,0.2)";
    ctx.lineWidth = 0.9;
    ctx.stroke();

    const progress = (t * 0.22 + i * 0.17) % 1;
    const px = (1 - progress) * (1 - progress) * p1.x + 2 * (1 - progress) * progress * mx + progress * progress * p2.x;
    const py = (1 - progress) * (1 - progress) * p1.y + 2 * (1 - progress) * progress * my + progress * progress * p2.y;
    ctx.beginPath();
    ctx.arc(px, py, 2, 0, Math.PI * 2);
    ctx.fillStyle = "rgba(80,255,210,0.8)";
    ctx.shadowColor = "#00ffaa";
    ctx.shadowBlur = 10;
    ctx.fill();
    ctx.shadowBlur = 0;
  });
}

export function drawScanSweep(ctx, cx, cy, radius, t) {
  const angle = t * 0.65;
  ctx.save();
  ctx.beginPath();
  ctx.arc(cx, cy, radius * 1.02, 0, Math.PI * 2);
  ctx.clip();
  const grad = ctx.createConicGradient(angle, cx, cy);
  grad.addColorStop(0, "rgba(0,255,170,0)");
  grad.addColorStop(0.05, "rgba(0,255,170,0.18)");
  grad.addColorStop(0.12, "rgba(0,255,170,0)");
  grad.addColorStop(1, "rgba(0,255,170,0)");
  ctx.beginPath();
  ctx.arc(cx, cy, radius * 1.03, 0, Math.PI * 2);
  ctx.fillStyle = grad;
  ctx.fill();
  ctx.restore();
}

export function drawLatLonGrid(ctx, cx, cy, radius, rot, latCount = 9, lonCount = 14) {
  ctx.save();
  ctx.beginPath();
  ctx.arc(cx, cy, radius, 0, Math.PI * 2);
  ctx.clip();

  for (let lat = 1; lat < latCount; lat++) {
    const phi = (lat / latCount) * Math.PI;
    ctx.beginPath();
    let started = false;
    for (let i = 0; i <= 72; i++) {
      const theta = (i / 72) * Math.PI * 2;
      const x = Math.sin(phi) * Math.cos(theta);
      const y = Math.cos(phi);
      const z = Math.sin(phi) * Math.sin(theta);
      const r = rotateY(x, y, z, rot);
      if (r.z < -0.08) { started = false; continue; }
      const p = project(r.x, r.y, r.z, cx, cy, radius);
      if (!started) { ctx.moveTo(p.x, p.y); started = true; }
      else ctx.lineTo(p.x, p.y);
    }
    ctx.strokeStyle = `rgba(95,255,210,${0.08 + Math.abs(Math.cos(phi)) * 0.12})`;
    ctx.lineWidth = 0.6;
    ctx.stroke();
  }

  for (let lon = 0; lon < lonCount; lon++) {
    const theta = (lon / lonCount) * Math.PI * 2;
    ctx.beginPath();
    let started = false;
    for (let i = 0; i <= 72; i++) {
      const phi = (i / 72) * Math.PI;
      const x = Math.sin(phi) * Math.cos(theta);
      const y = Math.cos(phi);
      const z = Math.sin(phi) * Math.sin(theta);
      const r = rotateY(x, y, z, rot);
      if (r.z < -0.08) { started = false; continue; }
      const p = project(r.x, r.y, r.z, cx, cy, radius);
      if (!started) { ctx.moveTo(p.x, p.y); started = true; }
      else ctx.lineTo(p.x, p.y);
    }
    ctx.strokeStyle = "rgba(95,255,210,0.1)";
    ctx.lineWidth = 0.5;
    ctx.stroke();
  }

  ctx.restore();
}

export function drawLandMasses(ctx, landPoints, cx, cy, radius, rot) {
  const projected = landPoints
    .map(({ x, y, z }) => {
      const r = rotateY(x, y, z, rot);
      return { ...project(r.x, r.y, r.z, cx, cy, radius), z: r.z };
    })
    .filter((p) => p.z > -0.05)
    .sort((a, b) => a.z - b.z);

  projected.forEach((p) => {
    const alpha = 0.18 + (p.z + 1) * 0.36;
    const dotR = 0.72 + p.scale * 1.2;
    ctx.beginPath();
    ctx.arc(p.x, p.y, dotR, 0, Math.PI * 2);
    ctx.fillStyle = `rgba(28,255,176,${alpha})`;
    ctx.fill();
  });
}

export function drawThreatHotspots(ctx, hotspots, cx, cy, radius, rot, t) {
  hotspots.forEach((spot, i) => {
    const unit = latLonToUnit(spot.lat, spot.lon);
    const r = rotateY(unit.x, unit.y, unit.z, rot);
    if (r.z < 0.05) return;

    const p = project(r.x, r.y, r.z, cx, cy, radius);
    const pulse = 0.55 + Math.sin(t * 2 + i * 1.1) * 0.45;
    const glowR = 6 + spot.intensity * 14 * pulse;

    const grad = ctx.createRadialGradient(p.x, p.y, 0, p.x, p.y, glowR);
    const alpha = spot.intensity * pulse;
    grad.addColorStop(0, `rgba(255,80,60,${alpha * 0.95})`);
    grad.addColorStop(0.35, `rgba(255,140,40,${alpha * 0.45})`);
    grad.addColorStop(1, "transparent");
    ctx.beginPath();
    ctx.arc(p.x, p.y, glowR, 0, Math.PI * 2);
    ctx.fillStyle = grad;
    ctx.fill();

    ctx.beginPath();
    ctx.arc(p.x, p.y, 2.2 + pulse * 0.8, 0, Math.PI * 2);
    ctx.fillStyle = `rgba(255,120,60,${0.7 + pulse * 0.3})`;
    ctx.shadowColor = "#ff5533";
    ctx.shadowBlur = 12;
    ctx.fill();
    ctx.shadowBlur = 0;
  });
}

/* ---------------------------------------------------------------------------
 * Google-Earth-style renderer (used by GlobalThreatMap)
 * --------------------------------------------------------------------------- */

export function drawEarthBase(ctx, cx, cy, radius) {
  // Atmosphere glow
  const glow = ctx.createRadialGradient(cx, cy, radius * 0.82, cx, cy, radius * 1.85);
  glow.addColorStop(0, "rgba(90,150,255,0.18)");
  glow.addColorStop(0.5, "rgba(50,100,220,0.05)");
  glow.addColorStop(1, "transparent");
  ctx.beginPath();
  ctx.arc(cx, cy, radius * 1.8, 0, Math.PI * 2);
  ctx.fillStyle = glow;
  ctx.fill();

  // Deep-blue oceans
  const ocean = ctx.createRadialGradient(
    cx - radius * 0.35,
    cy - radius * 0.3,
    radius * 0.05,
    cx,
    cy,
    radius * 1.05
  );
  ocean.addColorStop(0, "#143d6e");
  ocean.addColorStop(0.45, "#0d2b52");
  ocean.addColorStop(0.8, "#071c3a");
  ocean.addColorStop(1, "#040e20");
  ctx.beginPath();
  ctx.arc(cx, cy, radius, 0, Math.PI * 2);
  ctx.fillStyle = ocean;
  ctx.fill();

  // Rim light on the lit edge
  ctx.beginPath();
  ctx.arc(cx, cy, radius, 0, Math.PI * 2);
  ctx.strokeStyle = "rgba(120,190,255,0.5)";
  ctx.lineWidth = 1.4;
  ctx.stroke();

  // Night-side shading
  const shade = ctx.createRadialGradient(
    cx + radius * 0.45,
    cy + radius * 0.05,
    radius * 0.12,
    cx + radius * 0.45,
    cy + radius * 0.05,
    radius * 1.05
  );
  shade.addColorStop(0, "transparent");
  shade.addColorStop(0.55, "rgba(0,0,0,0.22)");
  shade.addColorStop(1, "rgba(0,0,0,0.68)");
  ctx.beginPath();
  ctx.arc(cx, cy, radius, 0, Math.PI * 2);
  ctx.fillStyle = shade;
  ctx.fill();
}

export function drawEarthGrid(ctx, cx, cy, radius, rot, latCount = 8, lonCount = 13) {
  ctx.save();
  ctx.beginPath();
  ctx.arc(cx, cy, radius, 0, Math.PI * 2);
  ctx.clip();

  for (let lat = 1; lat < latCount; lat++) {
    const phi = (lat / latCount) * Math.PI;
    ctx.beginPath();
    let started = false;
    for (let i = 0; i <= 72; i++) {
      const theta = (i / 72) * Math.PI * 2;
      const r = rotateY(Math.sin(phi) * Math.cos(theta), Math.cos(phi), Math.sin(phi) * Math.sin(theta), rot);
      if (r.z < -0.06) { started = false; continue; }
      const p = project(r.x, r.y, r.z, cx, cy, radius);
      if (!started) { ctx.moveTo(p.x, p.y); started = true; }
      else ctx.lineTo(p.x, p.y);
    }
    ctx.strokeStyle = `rgba(130,180,255,${0.06 + Math.abs(Math.cos(phi)) * 0.08})`;
    ctx.lineWidth = 0.5;
    ctx.stroke();
  }

  for (let lon = 0; lon < lonCount; lon++) {
    const theta = (lon / lonCount) * Math.PI * 2;
    ctx.beginPath();
    let started = false;
    for (let i = 0; i <= 72; i++) {
      const phi = (i / 72) * Math.PI;
      const r = rotateY(Math.sin(phi) * Math.cos(theta), Math.cos(phi), Math.sin(phi) * Math.sin(theta), rot);
      if (r.z < -0.06) { started = false; continue; }
      const p = project(r.x, r.y, r.z, cx, cy, radius);
      if (!started) { ctx.moveTo(p.x, p.y); started = true; }
      else ctx.lineTo(p.x, p.y);
    }
    ctx.strokeStyle = "rgba(130,180,255,0.07)";
    ctx.lineWidth = 0.4;
    ctx.stroke();
  }
  ctx.restore();
}

// Earth-tone landmasses (stable color hash from world coords)
export function drawEarthLand(ctx, landPoints, cx, cy, radius, rot) {
  const projected = landPoints
    .map(({ x, y, z }) => {
      const r = rotateY(x, y, z, rot);
      return { ...project(r.x, r.y, r.z, cx, cy, radius), z: r.z, wx: x, wy: y };
    })
    .filter((p) => p.z > -0.06)
    .sort((a, b) => a.z - b.z);

  projected.forEach((p) => {
    const lit = 0.45 + p.z * 0.5;
    const alpha = 0.4 + lit * 0.45;
    const dotR = 0.75 + p.scale * 1.25;
    const green = Math.sin(p.wx * 37.7 + p.wy * 11.3) > 0;
    ctx.beginPath();
    ctx.arc(p.x, p.y, dotR, 0, Math.PI * 2);
    ctx.fillStyle = green
      ? `rgba(52,118,60,${alpha})`
      : `rgba(104,80,42,${alpha})`;
    ctx.fill();
  });
}

// Warm city lights on a stable subset of land points (night view)
export function drawCityLights(ctx, landPoints, cx, cy, radius, rot, t) {
  landPoints.forEach(({ x, y, z }) => {
    if (Math.sin(x * 91.7 + y * 43.3 + z * 17.1) <= 0.94) return;
    const r = rotateY(x, y, z, rot);
    if (r.z < 0.05) return;
    const p = project(r.x, r.y, r.z, cx, cy, radius);
    const tw = 0.45 + Math.sin(t * 1.4 + x * 50) * 0.35;
    ctx.beginPath();
    ctx.arc(p.x, p.y, 0.6 + p.scale * 0.8, 0, Math.PI * 2);
    ctx.fillStyle = `rgba(255,214,120,${Math.max(0.12, tw * 0.5)})`;
    ctx.fill();
  });
}

// Red alert markers for live phishing hotspots (markers pre-projected: {x,y,z,count,typeColor})
export function drawThreatMarkers(ctx, markers, t) {
  markers.forEach((m, i) => {
    if (m.z < 0.05) return;
    const size = Math.min(15, 3.5 + Math.sqrt(m.count) * 2.2);
    const pulse = 0.55 + Math.sin(t * 2.2 + i * 1.31) * 0.45;

    // Expanding alert ring
    const ringP = (t * 0.3 + i * 0.17) % 1;
    ctx.beginPath();
    ctx.arc(m.x, m.y, size + 4 + ringP * 20, 0, Math.PI * 2);
    ctx.globalAlpha = (1 - ringP) * 0.5;
    ctx.strokeStyle = "rgba(255,60,50,0.9)";
    ctx.lineWidth = 1.3;
    ctx.stroke();
    ctx.globalAlpha = 1;

    // Red glow
    const grad = ctx.createRadialGradient(m.x, m.y, 0, m.x, m.y, size * 3);
    grad.addColorStop(0, `rgba(255,55,45,${0.7 * pulse})`);
    grad.addColorStop(0.4, `rgba(255,95,40,${0.32 * pulse})`);
    grad.addColorStop(1, "transparent");
    ctx.beginPath();
    ctx.arc(m.x, m.y, size * 3, 0, Math.PI * 2);
    ctx.fillStyle = grad;
    ctx.fill();

    // Attack-type ring
    ctx.beginPath();
    ctx.arc(m.x, m.y, size + 4, 0, Math.PI * 2);
    ctx.globalAlpha = 0.6 + pulse * 0.4;
    ctx.strokeStyle = m.typeColor || "#ff453a";
    ctx.lineWidth = 1.7;
    ctx.stroke();
    ctx.globalAlpha = 1;

    // Hot core
    const core = ctx.createRadialGradient(m.x - size * 0.3, m.y - size * 0.3, size * 0.05, m.x, m.y, size * 1.05);
    core.addColorStop(0, "#fff5f0");
    core.addColorStop(0.4, "#ff5a3c");
    core.addColorStop(1, "#e01212");
    ctx.beginPath();
    ctx.arc(m.x, m.y, size, 0, Math.PI * 2);
    ctx.fillStyle = core;
    ctx.shadowColor = "#ff2a1a";
    ctx.shadowBlur = 14;
    ctx.fill();
    ctx.shadowBlur = 0;
  });
}

