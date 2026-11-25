/**
 * components/SignalBreakdown.jsx — Monochrome signal bars.
 *
 * Nothing OS aesthetic:
 *   - White/gray fill bars for normal signals
 *   - Red fill only for high-risk signals (score < 40)
 *   - Hairline borders, monospace labels
 */

import { useEffect, useRef } from 'react';

// Nothing OS color logic: only high-risk gets red
function getBarColor(score) {
  if (score >= 70) return { bar: '#ffffff', text: '#ffffff' };
  if (score >= 40) return { bar: '#666666', text: '#888888' };
  return { bar: '#FF0000', text: '#FF0000' };
}

const SIGNAL_ICONS = {
  'SSL Certificate':                       '◈',
  'Domain Age (WHOIS)':                    '◷',
  'Phishing Heuristics':                   '◎',
  'PQC Readiness':                         '◯',
  'Email Authentication (SPF/DKIM/DMARC)': '◆',
  'Content Heuristics':                    '◉',
  'Permission Risk Score':                 '◈',
  'App Metadata Score':                    '◎',
};

function SignalBar({ label, score, index }) {
  const barRef = useRef(null);
  const { bar, text } = getBarColor(score);
  const pct = Math.max(0, Math.min(100, score));

  useEffect(() => {
    const timer = setTimeout(() => {
      if (barRef.current) barRef.current.style.width = `${pct}%`;
    }, 80 + index * 60);
    return () => clearTimeout(timer);
  }, [pct, index]);

  return (
    <div
      className="flex items-center gap-3 animate-slide-up"
      style={{ animationDelay: `${index * 50}ms` }}
    >
      {/* Label */}
      <div className="w-48 flex-shrink-0 flex items-center gap-2 min-w-0">
        <span className="text-white/30 text-xs font-mono flex-shrink-0">
          {SIGNAL_ICONS[label] || '◎'}
        </span>
        <span className="text-white/70 text-xs font-mono truncate uppercase tracking-wide">
          {label}
        </span>
      </div>

      {/* Bar track */}
      <div className="flex-1 h-[3px] bg-white/5 overflow-hidden relative">
        <div
          ref={barRef}
          className="absolute left-0 top-0 h-full transition-all duration-700 ease-out"
          style={{ width: '0%', backgroundColor: bar }}
        />
      </div>

      {/* Score number */}
      <div
        className="w-10 text-right text-xs font-bold font-mono tabular-nums flex-shrink-0"
        style={{ color: text }}
      >
        {Math.round(score)}
      </div>
    </div>
  );
}

export default function SignalBreakdown({ breakdown }) {
  if (!breakdown) return null;
  const entries = Object.entries(breakdown);

  return (
    <div className="nm-card p-5 animate-fade-in">
      <h3 className="section-title">SIGNAL BREAKDOWN</h3>

      {/* Legend */}
      <div className="flex items-center gap-5 mb-5 text-[10px] font-mono text-white/30 uppercase tracking-widest">
        <span className="flex items-center gap-1.5">
          <span className="w-2 h-[2px] bg-white inline-block" /> LOW RISK ≥70
        </span>
        <span className="flex items-center gap-1.5">
          <span className="w-2 h-[2px] bg-gray-500 inline-block" /> MED 40–69
        </span>
        <span className="flex items-center gap-1.5">
          <span className="w-2 h-[2px] bg-red-500 inline-block" /> HIGH &lt;40
        </span>
      </div>

      <div className="space-y-3.5">
        {entries.map(([label, score], i) => (
          <SignalBar key={label} label={label} score={score} index={i} />
        ))}
      </div>

      <p className="mt-4 text-[10px] font-mono text-white/20 uppercase tracking-wide">
        EACH SCORE 0–100 · 100 = MAXIMALLY SAFE · WEIGHTED AVERAGE
      </p>
    </div>
  );
}
