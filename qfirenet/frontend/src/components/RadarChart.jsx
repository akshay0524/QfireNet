/**
 * components/RadarChart.jsx — Pure SVG Multi-Signal Radar Chart
 *
 * Visualizes multi-dimensional trust signal breakdowns at a glance
 * using the sunset sky color palette.
 */

import { useMemo } from 'react';

function polarToCartesian(cx, cy, r, angleDeg) {
  const rad = ((angleDeg - 90) * Math.PI) / 180;
  return {
    x: cx + r * Math.cos(rad),
    y: cy + r * Math.sin(rad),
  };
}

function buildPolygonPoints(cx, cy, maxR, values, angles) {
  return values.map((v, i) => {
    const r = (v / 100) * maxR;
    const { x, y } = polarToCartesian(cx, cy, r, angles[i]);
    return `${x},${y}`;
  }).join(' ');
}

function GridRing({ cx, cy, maxR, pct, n }) {
  const r = (pct / 100) * maxR;
  const points = Array.from({ length: n }, (_, i) => {
    const { x, y } = polarToCartesian(cx, cy, r, (360 / n) * i);
    return `${x},${y}`;
  }).join(' ');
  return (
    <polygon
      points={points}
      fill="none"
      stroke="rgba(255,255,255,0.07)"
      strokeWidth="1"
    />
  );
}

function scoreColor(score) {
  if (score >= 70) return '#4E9F76';
  if (score >= 40) return '#E89D86';
  return '#AD504F';
}

export default function RadarChart({ breakdown, size = 220 }) {
  const entries = useMemo(() => Object.entries(breakdown || {}), [breakdown]);
  if (!entries.length) return null;

  const n = entries.length;
  const cx = size / 2;
  const cy = size / 2;
  const maxR = (size / 2) * 0.75;
  const angles = Array.from({ length: n }, (_, i) => (360 / n) * i);
  const values = entries.map(([, v]) => Math.max(0, Math.min(100, v)));
  const avgScore = values.reduce((a, b) => a + b, 0) / values.length;
  const fillColor = scoreColor(avgScore);

  const dataPoints = buildPolygonPoints(cx, cy, maxR, values, angles);

  const axisLines = angles.map((angle, i) => {
    const { x, y } = polarToCartesian(cx, cy, maxR, angle);
    return <line key={i} x1={cx} y1={cy} x2={x} y2={y} stroke="rgba(255,255,255,0.08)" strokeWidth="1" />;
  });

  const labels = entries.map(([label], i) => {
    const { x, y } = polarToCartesian(cx, cy, maxR + 22, angles[i]);
    const short = label
      .replace('Email Authentication (SPF/DKIM/DMARC)', 'Email Auth')
      .replace('Permission Risk Score', 'Permissions')
      .replace('App Metadata Score', 'Metadata')
      .replace('Phishing Heuristics', 'Phishing')
      .replace('Domain Age (WHOIS)', 'Domain Age')
      .replace('SSL Certificate', 'SSL')
      .replace('PQC Readiness', 'PQC')
      .replace('Content Heuristics', 'Content');

    const anchor = x < cx - 5 ? 'end' : x > cx + 5 ? 'start' : 'middle';
    return (
      <text
        key={label}
        x={x} y={y}
        textAnchor={anchor}
        dominantBaseline="middle"
        fill="rgba(203, 213, 225, 0.85)"
        fontSize="9.5"
        fontFamily="Plus Jakarta Sans, sans-serif"
        fontWeight="600"
      >
        {short}
      </text>
    );
  });

  const dots = values.map((v, i) => {
    const r = (v / 100) * maxR;
    const { x, y } = polarToCartesian(cx, cy, r, angles[i]);
    return (
      <circle
        key={i}
        cx={x} cy={y} r="3"
        fill={fillColor}
        stroke="rgba(11, 18, 29, 0.8)"
        strokeWidth="1"
      />
    );
  });

  return (
    <svg
      width={size}
      height={size}
      viewBox={`0 0 ${size} ${size}`}
      style={{ overflow: 'visible' }}
    >
      {[25, 50, 75, 100].map(pct => (
        <GridRing key={pct} cx={cx} cy={cy} maxR={maxR} pct={pct} n={n} />
      ))}

      {axisLines}

      <polygon
        points={dataPoints}
        fill={`${fillColor}28`}
        stroke={fillColor}
        strokeWidth="1.75"
        strokeLinejoin="round"
        className="radar-polygon"
        style={{ filter: `drop-shadow(0 0 8px ${fillColor}55)` }}
      />

      {dots}
      {labels}
    </svg>
  );
}
