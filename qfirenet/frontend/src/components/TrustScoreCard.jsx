/**
 * components/TrustScoreCard.jsx — Dot-matrix trust score display.
 *
 * Nothing OS aesthetic:
 *   - Large monospace 3-digit number (e.g. "073")
 *   - Dot-matrix grid below that fills proportionally to the score
 *   - Low = white, Medium = gray, High = red (#FF0000)
 *   - Risk level label: sharp uppercase tag
 */

import { useEffect, useState } from 'react';

const RISK_CONFIG = {
  Low:    { color: '#ffffff', label: 'LOW RISK',    tag: 'border-white/40 text-white' },
  Medium: { color: '#aaaaaa', label: 'MEDIUM RISK', tag: 'border-white/25 text-gray-400' },
  High:   { color: '#FF0000', label: 'HIGH RISK',   tag: 'border-red-500/60 text-red-500' },
};

// Dot grid — 10 columns × 5 rows = 50 dots
const COLS = 10;
const ROWS = 5;
const TOTAL_DOTS = COLS * ROWS;

function DotGrid({ score, color }) {
  const filledCount = Math.round((score / 100) * TOTAL_DOTS);

  return (
    <div
      className="grid gap-[3px] mt-4"
      style={{
        gridTemplateColumns: `repeat(${COLS}, minmax(0, 1fr))`,
        width: '100%',
        maxWidth: '200px',
      }}
      aria-label={`Score visualization: ${filledCount} of ${TOTAL_DOTS} dots filled`}
    >
      {Array.from({ length: TOTAL_DOTS }, (_, i) => {
        const filled = i < filledCount;
        return (
          <div
            key={i}
            style={{
              width: '100%',
              paddingBottom: '100%',
              borderRadius: '1px',
              backgroundColor: filled ? color : 'rgba(255,255,255,0.06)',
              transition: `background-color 150ms ease-out ${i * 8}ms`,
            }}
          />
        );
      })}
    </div>
  );
}

export default function TrustScoreCard({ trustScore, riskLevel, pqcReady }) {
  const config = RISK_CONFIG[riskLevel] || RISK_CONFIG.Medium;
  const score = Math.max(0, Math.min(100, Math.round(trustScore ?? 0)));

  // Animated counter from 0 → score
  const [displayed, setDisplayed] = useState(0);
  useEffect(() => {
    let start = null;
    const duration = 800;
    const from = 0;
    const to = score;
    const raf = (ts) => {
      if (!start) start = ts;
      const progress = Math.min((ts - start) / duration, 1);
      const eased = 1 - Math.pow(1 - progress, 3);
      setDisplayed(Math.round(from + (to - from) * eased));
      if (progress < 1) requestAnimationFrame(raf);
    };
    requestAnimationFrame(raf);
  }, [score]);

  const formatted = String(displayed).padStart(3, '0');

  return (
    <div className="nm-card p-6 flex flex-col items-center animate-fade-in">
      {/* Scan type label */}
      <p className="text-[9px] font-mono uppercase tracking-[0.25em] text-white/30 mb-4">
        TRUST SCORE
      </p>

      {/* Dot-matrix number */}
      <div
        className="font-mono font-bold leading-none tracking-widest select-none"
        style={{
          fontSize: 'clamp(3rem, 8vw, 5rem)',
          color: config.color,
          textShadow: riskLevel === 'High'
            ? '0 0 30px rgba(255,0,0,0.5)'
            : 'none',
          fontVariantNumeric: 'tabular-nums',
        }}
        aria-label={`Trust score: ${score} out of 100`}
      >
        {formatted}
      </div>

      <p className="text-[9px] font-mono text-white/25 mt-1 tracking-widest uppercase">
        / 100
      </p>

      {/* Dot grid visualization */}
      <DotGrid score={score} color={config.color} />

      {/* Risk level badge */}
      <div className="mt-5">
        <span
          className={`inline-flex items-center px-3 py-1 text-[10px] font-mono font-bold uppercase tracking-[0.15em] border ${config.tag}`}
          style={{ borderRadius: '2px' }}
        >
          {config.label}
        </span>
      </div>

      {/* Subtitle */}
      <p className="mt-3 text-white/30 text-[10px] font-mono text-center leading-relaxed uppercase tracking-wide">
        {score >= 70
          ? 'STRONG TRUST SIGNALS DETECTED'
          : score >= 40
          ? 'ANOMALIES DETECTED — EXERCISE CAUTION'
          : 'HIGH RISK — DO NOT PROCEED'}
      </p>

      {/* PQC badge */}
      {pqcReady !== undefined && (
        <div className="mt-4">
          <span
            className={`inline-flex items-center gap-1.5 px-3 py-1 text-[10px] font-mono font-bold uppercase tracking-widest border ${
              pqcReady
                ? 'border-white/30 text-white'
                : 'border-white/10 text-white/25'
            }`}
            style={{ borderRadius: '2px' }}
          >
            <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.5}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M7.864 4.243A7.5 7.5 0 0119.5 10.5c0 2.92-.556 5.709-1.568 8.268M5.742 6.364A7.465 7.465 0 004.5 10.5a7.464 7.464 0 01-1.15 3.993m1.989 3.559A11.209 11.209 0 008.25 10.5a3.75 3.75 0 117.5 0c0 .527-.021 1.049-.064 1.565M12 10.5a14.94 14.94 0 01-3.6 9.75m6.633-4.596a18.666 18.666 0 01-2.485 5.33" />
            </svg>
            {pqcReady ? 'PQC READY' : 'NO PQC'}
          </span>
        </div>
      )}
    </div>
  );
}
