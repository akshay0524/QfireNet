/**
 * pages/Results.jsx — Nothing OS scan result detail page.
 *
 * - Monochrome scan type badges (no color differentiation)
 * - Red only for High Risk
 * - Hairline card borders, sharp corners
 * - Space Mono headings
 */

import { useState, useEffect } from 'react';
import { useParams, useNavigate, useLocation, Link } from 'react-router-dom';
import { historyAPI } from '../api/client';
import TrustScoreCard from '../components/TrustScoreCard';
import SignalBreakdown from '../components/SignalBreakdown';
import ExplanationPanel from '../components/ExplanationPanel';
import RadarChart from '../components/RadarChart';
import PQCBadge from '../components/PQCBadge';
import { useAuth } from '../App';

function ScanTypeBadge({ type }) {
  const cfg = {
    website: { sym: '◈', label: 'URL SCAN' },
    email:   { sym: '◆', label: 'EMAIL SCAN' },
    apk:     { sym: '◉', label: 'APK SCAN' },
  };
  const c = cfg[type] || cfg.website;
  return (
    <span className="inline-flex items-center gap-1.5 px-2.5 py-1 border border-white/15
      text-[10px] font-mono font-bold uppercase tracking-widest text-white/60"
      style={{ borderRadius: '2px' }}>
      {c.sym} {c.label}
    </span>
  );
}

export default function Results() {
  const { scanId } = useParams();
  const navigate = useNavigate();
  const location = useLocation();
  const { user } = useAuth();

  const [result, setResult] = useState(location.state?.result || null);
  const [loading, setLoading] = useState(!result);
  const [error, setError] = useState('');

  useEffect(() => {
    if (result) return;
    if (!user) {
      setError('Please log in to view saved scan reports.');
      setLoading(false);
      return;
    }
    historyAPI.getHistoryItem(scanId)
      .then(res => { setResult(res.data); setLoading(false); })
      .catch(err => {
        setError(err.response?.data?.detail || 'Failed to load scan report.');
        setLoading(false);
      });
  }, [scanId, user]);

  const formatDate = (iso) => {
    const d = new Date(iso);
    return d.toLocaleDateString('en-IN', {
      day: '2-digit', month: 'short', year: 'numeric',
      hour: '2-digit', minute: '2-digit',
    });
  };

  if (loading) return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
      <div className="space-y-4">
        <div className="skeleton h-6 w-36" />
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
          <div className="skeleton h-64" />
          <div className="lg:col-span-2 skeleton h-64" />
        </div>
        <div className="skeleton h-48" />
      </div>
    </div>
  );

  if (error) return (
    <div className="max-w-xl mx-auto px-4 py-24 text-center">
      <div className="nm-card p-12">
        <div className="text-3xl font-mono text-white/20 mb-4">⚠</div>
        <h2 className="text-white text-base font-mono font-bold mb-2 uppercase tracking-widest">
          REPORT UNAVAILABLE
        </h2>
        <p className="text-white/40 text-xs font-mono mb-8 uppercase tracking-wide">{error}</p>
        <div className="flex gap-3 justify-center">
          <button onClick={() => navigate(-1)} className="btn-ghost text-[10px]">
            ← BACK
          </button>
          <Link to="/dashboard" className="btn-primary text-[10px]">
            NEW SCAN
          </Link>
        </div>
      </div>
    </div>
  );

  if (!result) return null;

  const {
    scan_type, input_summary, trust_score, risk_level,
    breakdown, raw_results, explanation, scanned_at,
  } = result;

  const ssl        = raw_results?.ssl || {};
  const whois      = raw_results?.whois || {};
  const phishing   = raw_results?.phishing || {};
  const pqc        = raw_results?.pqc || {};
  const headers    = raw_results?.headers || {};
  const content    = raw_results?.content || {};
  const extraction = raw_results?.extraction || {};
  const risk       = raw_results?.risk || {};

  const isHighRisk = risk_level === 'High';

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 animate-fade-in">

      {/* ── Header / breadcrumb ──────────────────────────────────────── */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 mb-8">
        <div>
          <div className="flex items-center gap-3 mb-2.5">
            <button
              onClick={() => navigate(-1)}
              className="text-white/30 hover:text-white transition-colors text-[10px] font-mono uppercase tracking-widest flex items-center gap-1"
            >
              ← BACK
            </button>
            <span className="text-white/15 font-mono">/</span>
            <ScanTypeBadge type={scan_type} />
            {isHighRisk && (
              <span className="inline-flex items-center px-2 py-0.5 border border-red-500/50 bg-red-500/5
                text-red-500 text-[9px] font-mono font-bold uppercase tracking-widest"
                style={{ borderRadius: '2px' }}>
                ⚠ HIGH RISK
              </span>
            )}
          </div>
          <h1 className="text-white text-base font-mono font-bold truncate max-w-lg uppercase tracking-wide"
            title={input_summary}>
            {input_summary}
          </h1>
          {scanned_at && (
            <p className="text-white/25 text-[10px] font-mono mt-1 uppercase tracking-widest">
              SCANNED {formatDate(scanned_at)}
            </p>
          )}
        </div>
        <Link to="/dashboard" className="btn-primary text-[10px] flex-shrink-0 flex items-center gap-2">
          <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.5}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M12 4.5v15m7.5-7.5h-15" />
          </svg>
          NEW SCAN
        </Link>
      </div>

      {/* ── Main grid ────────────────────────────────────────────────── */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4 mb-4">

        {/* Left: Score + radar + type-specific info */}
        <div className="lg:col-span-1 space-y-4">
          <TrustScoreCard
            trustScore={trust_score}
            riskLevel={risk_level}
            pqcReady={scan_type === 'website' ? pqc?.pqc_ready : undefined}
          />

          {/* Radar chart */}
          {breakdown && Object.keys(breakdown).length >= 3 && (
            <div className="nm-card p-5">
              <p className="section-title">SIGNAL RADAR</p>
              <div className="flex justify-center py-2">
                <RadarChart breakdown={breakdown} size={200} />
              </div>
            </div>
          )}

          {/* Website details */}
          {scan_type === 'website' && (
            <div className="nm-card p-4 space-y-2.5">
              <p className="section-title mb-2">CONNECTION DETAILS</p>
              {[
                ['SSL STATUS', ssl.is_valid ? '✓ VALID' : '✕ INVALID'],
                ['EXPIRES IN', ssl.days_until_expiry != null ? `${ssl.days_until_expiry} DAYS` : '—'],
                ['TLS VERSION', ssl.tls_version || '—'],
                ['DOMAIN AGE', whois.domain_age_days != null ? `${whois.domain_age_days} DAYS` : '—'],
                ['REGISTRAR', whois.registrar ? whois.registrar.slice(0, 30).toUpperCase() : '—'],
              ].map(([k, v]) => (
                <div key={k} className="flex justify-between items-center">
                  <span className="text-white/30 text-[10px] font-mono uppercase tracking-widest">{k}</span>
                  <span className={`text-[10px] font-mono font-bold uppercase ${
                    k === 'SSL STATUS' && !ssl.is_valid ? 'text-red-500' :
                    k === 'SSL STATUS' ? 'text-white' : 'text-white/60'
                  }`}>{v}</span>
                </div>
              ))}
            </div>
          )}

          {/* Email Auth */}
          {scan_type === 'email' && (
            <div className="nm-card p-4 space-y-2.5">
              <p className="section-title mb-2">EMAIL AUTHENTICATION</p>
              {[
                ['SPF', headers.spf_pass],
                ['DKIM', headers.dkim_pass],
                ['DMARC', headers.dmarc_pass],
              ].map(([label, pass]) => (
                <div key={label} className="flex items-center justify-between">
                  <span className="text-white/30 text-[10px] font-mono uppercase tracking-widest">{label}</span>
                  <span className={`text-[10px] font-mono font-bold ${pass ? 'text-white' : 'text-red-500'}`}>
                    {pass ? '✓ PASS' : '✕ FAIL'}
                  </span>
                </div>
              ))}
              {headers.sender_domain_mismatch && (
                <div className="pt-2 border-t border-white/6">
                  <span className="text-red-500 text-[10px] font-mono font-bold uppercase tracking-widest">
                    ⚠ SENDER DOMAIN MISMATCH
                  </span>
                </div>
              )}
              {headers.from_address && (
                <div className="pt-2 border-t border-white/6">
                  <span className="text-white/20 text-[9px] font-mono block mb-1 uppercase">FROM</span>
                  <span className="text-white/50 text-[10px] font-mono break-all">{headers.from_address}</span>
                </div>
              )}
            </div>
          )}

          {/* APK Info */}
          {scan_type === 'apk' && (
            <div className="nm-card p-4 space-y-2.5">
              <p className="section-title mb-2">APP INFO</p>
              {[
                ['NAME',        extraction.app_name || '—'],
                ['PACKAGE',     extraction.package_name?.slice(0, 28) + '...' || '—'],
                ['PERMISSIONS', extraction.permission_count ?? '—'],
                ['TARGET SDK',  extraction.target_sdk || '—'],
                ['MIN SDK',     extraction.min_sdk_version || '—'],
              ].map(([k, v]) => (
                <div key={k} className="flex justify-between">
                  <span className="text-white/30 text-[10px] font-mono uppercase tracking-widest">{k}</span>
                  <span className="text-white/60 text-[10px] font-mono font-bold">{v}</span>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Right: Breakdown + explanation + extras */}
        <div className="lg:col-span-2 space-y-4">

          {breakdown && <SignalBreakdown breakdown={breakdown} />}

          <ExplanationPanel explanation={explanation} />

          {/* PQC badge */}
          {scan_type === 'website' && pqc && <PQCBadge pqcResult={pqc} />}

          {/* Phishing indicators */}
          {scan_type === 'website' && phishing?.risk_indicators?.length > 0 && (
            <div className="nm-card p-5 animate-fade-in border-red-500/20">
              <h3 className="section-title text-red-500/70">⚠ PHISHING INDICATORS</h3>
              <div className="space-y-1.5">
                {phishing.risk_indicators.map((ind, i) => (
                  <div key={i} className="flex items-start gap-3 p-2.5 border border-red-500/15 bg-red-500/3"
                    style={{ borderRadius: '2px' }}>
                    <span className="text-red-500 text-[10px] mt-0.5 flex-shrink-0 font-mono font-bold">✕</span>
                    <span className="text-white/60 text-xs leading-relaxed font-sans">{ind}</span>
                  </div>
                ))}
              </div>
              {phishing.url_entropy != null && (
                <p className="mt-3 text-white/20 text-[10px] font-mono uppercase">
                  URL ENTROPY: {phishing.url_entropy} BITS · DOMAIN ENTROPY: {phishing.domain_entropy} BITS
                </p>
              )}
            </div>
          )}

          {/* High-risk APK permissions */}
          {scan_type === 'apk' && risk?.high_risk_permissions?.length > 0 && (
            <div className="nm-card p-5 animate-fade-in border-red-500/20">
              <h3 className="section-title text-red-500/70">HIGH-RISK PERMISSIONS</h3>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-1.5">
                {risk.high_risk_permissions.map((perm) => {
                  const tier = risk.permission_breakdown?.[perm] || 'High';
                  const tierColor = tier === 'Critical' ? 'text-red-500' : 'text-white/50';
                  return (
                    <div key={perm} className="flex items-center justify-between py-2 px-3 border border-white/6"
                      style={{ borderRadius: '2px' }}>
                      <span className="text-white/50 text-[10px] font-mono truncate">
                        {perm.replace('android.permission.', '')}
                      </span>
                      <span className={`text-[10px] font-mono font-bold ml-3 flex-shrink-0 uppercase tracking-widest ${tierColor}`}>
                        {tier}
                      </span>
                    </div>
                  );
                })}
              </div>
              {risk.tier_counts && (
                <div className="flex gap-5 mt-4 pt-4 border-t border-white/6">
                  {Object.entries(risk.tier_counts).map(([tier, count]) => (
                    <div key={tier} className="text-center">
                      <div className="text-sm font-mono font-bold text-white">{count}</div>
                      <div className="text-[9px] font-mono text-white/30 uppercase tracking-widest">{tier}</div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {/* Email content heuristics */}
          {scan_type === 'email' && content?.risk_indicators?.length > 0 && (
            <div className="nm-card p-5 animate-fade-in border-white/10">
              <h3 className="section-title">CONTENT RISK INDICATORS</h3>
              <div className="space-y-1.5">
                {content.risk_indicators.map((ind, i) => (
                  <div key={i} className="flex items-start gap-3 p-2.5 border border-white/8"
                    style={{ borderRadius: '2px' }}>
                    <span className="text-white/40 text-[10px] mt-0.5 flex-shrink-0 font-mono font-bold">⚠</span>
                    <span className="text-white/60 text-xs leading-relaxed font-sans">{ind}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>

      {/* ── Footer actions ────────────────────────────────────────────── */}
      <div className="flex flex-col sm:flex-row items-center justify-between gap-4 pt-5 border-t border-white/6">
        <p className="text-white/20 text-[10px] font-mono uppercase tracking-widest">
          REPORT #{result.id || scanId} · GENERATED BY QFIRENET ENGINE
        </p>
        <div className="flex gap-2">
          {user && (
            <Link to="/history" className="btn-ghost text-[10px] px-4 py-2">
              VIEW HISTORY
            </Link>
          )}
          <Link to="/dashboard" className="btn-primary text-[10px] px-4 py-2">
            NEW SCAN
          </Link>
        </div>
      </div>
    </div>
  );
}
