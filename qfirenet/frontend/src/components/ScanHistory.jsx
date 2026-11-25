/**
 * components/ScanHistory.jsx — Nothing OS scan history list.
 *
 * Hairline bottom borders, monochrome badges.
 * High Risk = red, Medium = gray, Low = white.
 */

import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { historyAPI } from '../api/client';

const SCAN_TYPE_CONFIG = {
  website: { sym: '◈', label: 'URL',   color: 'text-white/60 border-white/15' },
  email:   { sym: '◆', label: 'EMAIL', color: 'text-white/60 border-white/15' },
  apk:     { sym: '◉', label: 'APK',   color: 'text-white/60 border-white/15' },
};

const RISK_STYLES = {
  Low:    { cls: 'text-white border-white/30',   label: 'LOW' },
  Medium: { cls: 'text-gray-400 border-gray-500/30', label: 'MEDIUM' },
  High:   { cls: 'text-red-500 border-red-500/40',  label: 'HIGH' },
};

function MiniScore({ score }) {
  const color = score >= 70 ? '#ffffff' : score >= 40 ? '#666666' : '#FF0000';
  return (
    <div
      className="font-mono font-bold tabular-nums text-sm leading-none flex-shrink-0 w-8 text-right"
      style={{ color }}
    >
      {Math.round(score)}
    </div>
  );
}

const FILTER_TABS = [
  { id: null,      label: 'ALL' },
  { id: 'website', label: 'URL' },
  { id: 'email',   label: 'EMAIL' },
  { id: 'apk',     label: 'APK' },
];

export default function ScanHistory() {
  const navigate = useNavigate();
  const [scans, setScans]     = useState([]);
  const [total, setTotal]     = useState(0);
  const [page, setPage]       = useState(1);
  const [filter, setFilter]   = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError]     = useState('');
  const PAGE_SIZE = 10;

  useEffect(() => { setPage(1); }, [filter]);
  useEffect(() => { fetchHistory(page, filter); }, [page, filter]);

  const fetchHistory = async (p, scanType) => {
    setLoading(true);
    setError('');
    try {
      const res = await historyAPI.getHistory(p, PAGE_SIZE, scanType);
      setScans(res.data.items);
      setTotal(res.data.total);
    } catch (_) {
      setError('Failed to load scan history.');
    } finally {
      setLoading(false);
    }
  };

  const totalPages = Math.ceil(total / PAGE_SIZE);

  const formatDate = (iso) => {
    const d = new Date(iso);
    return d.toLocaleDateString('en-IN', {
      day: '2-digit', month: 'short', year: 'numeric',
      hour: '2-digit', minute: '2-digit',
    });
  };

  if (loading) return (
    <div className="space-y-px">
      {[...Array(5)].map((_, i) => (
        <div key={i} className="skeleton h-16 w-full" />
      ))}
    </div>
  );

  if (error) return (
    <div className="nm-card p-8 text-center">
      <p className="text-red-500 text-xs font-mono uppercase tracking-widest">{error}</p>
      <button onClick={() => fetchHistory(page, filter)} className="btn-ghost mt-4 text-xs">
        RETRY
      </button>
    </div>
  );

  return (
    <div className="animate-fade-in">

      {/* Filter tabs */}
      <div className="flex gap-0 mb-6 border border-white/10" style={{ borderRadius: '2px' }}>
        {FILTER_TABS.map((tab) => (
          <button
            key={String(tab.id)}
            onClick={() => setFilter(tab.id)}
            className={`px-5 py-2 text-[10px] font-mono font-bold uppercase tracking-[0.18em] transition-all duration-150 flex-1 ${
              filter === tab.id
                ? 'bg-white text-black'
                : 'text-white/40 hover:text-white hover:bg-white/5'
            }`}
          >
            {tab.label}
          </button>
        ))}
        {total > 0 && (
          <span className="px-4 py-2 text-[10px] text-white/20 font-mono self-center">
            {total}
          </span>
        )}
      </div>

      {/* Empty state */}
      {scans.length === 0 && (
        <div className="nm-card p-12 text-center animate-fade-in">
          <p className="text-white/30 text-xs font-mono uppercase tracking-widest">
            NO SCAN HISTORY FOUND
          </p>
          <p className="text-white/15 text-[10px] font-mono mt-2 uppercase">
            RUN YOUR FIRST SCAN FROM THE DASHBOARD
          </p>
        </div>
      )}

      {/* Rows list */}
      <div className="border-t border-white/8">
        {scans.map((scan, index) => {
          const typeConf = SCAN_TYPE_CONFIG[scan.scan_type] || { sym: '◎', label: scan.scan_type, color: 'text-white/40' };
          const riskConf = RISK_STYLES[scan.risk_level] || RISK_STYLES.Medium;
          const excerpt  = scan.explanation?.slice(0, 90) + (scan.explanation?.length > 90 ? '…' : '') || '';

          return (
            <button
              key={scan.id}
              onClick={() => navigate(`/results/${scan.id}`)}
              className="w-full border-b border-white/6 py-3.5 px-0 flex items-center gap-4
                hover:bg-white/3 text-left transition-colors duration-150 group"
              style={{ animationDelay: `${index * 30}ms` }}
            >
              {/* Mini score */}
              <MiniScore score={scan.trust_score} />

              {/* Content */}
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 mb-1 flex-wrap">
                  {/* Scan type */}
                  <span className={`inline-flex items-center gap-1 px-2 py-0.5 text-[9px] font-mono font-bold border uppercase tracking-widest ${typeConf.color}`}
                    style={{ borderRadius: '2px' }}>
                    {typeConf.sym} {typeConf.label}
                  </span>
                  {/* Risk level */}
                  <span className={`inline-flex items-center px-2 py-0.5 text-[9px] font-mono font-bold border uppercase tracking-widest ${riskConf.cls}`}
                    style={{ borderRadius: '2px' }}>
                    {riskConf.label}
                  </span>
                  <span className="text-white/20 text-[9px] font-mono">{formatDate(scan.scanned_at)}</span>
                </div>
                <p className="text-white/80 text-xs font-mono truncate mb-0.5">{scan.input_summary}</p>
                {excerpt && (
                  <p className="text-white/30 text-[10px] truncate leading-relaxed font-sans">{excerpt}</p>
                )}
              </div>

              {/* Arrow */}
              <svg className="w-3 h-3 text-white/20 group-hover:text-white/60 transition-colors flex-shrink-0"
                fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M8.25 4.5l7.5 7.5-7.5 7.5" />
              </svg>
            </button>
          );
        })}
      </div>

      {/* Pagination */}
      {totalPages > 1 && (
        <div className="flex items-center justify-between mt-5 pt-4 border-t border-white/8">
          <p className="text-white/20 text-[10px] font-mono uppercase">
            {((page - 1) * PAGE_SIZE) + 1}–{Math.min(page * PAGE_SIZE, total)} OF {total}
          </p>
          <div className="flex gap-2">
            <button
              onClick={() => setPage((p) => Math.max(1, p - 1))}
              disabled={page === 1}
              className="btn-ghost text-[10px] px-3 py-1.5 disabled:opacity-20"
            >
              ← PREV
            </button>
            <span className="flex items-center px-3 py-1.5 text-white/30 text-[10px] font-mono">
              {page} / {totalPages}
            </span>
            <button
              onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
              disabled={page === totalPages}
              className="btn-ghost text-[10px] px-3 py-1.5 disabled:opacity-20"
            >
              NEXT →
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
