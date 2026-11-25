/**
 * components/ThreatCounterPanel.jsx — Live Threat Stats + Feed Panel
 *
 * - Polls /threat-events/stats every 20 seconds (real data)
 * - Falls back to demo/seed data when backend is empty or unreachable
 * - Auto-generates new simulated events every 12s as a simulation layer
 *   (real scan events take priority and override demo data once they exist)
 * - Rolling live feed showing last 8 events with risk level, entity, country, time
 */

import { useState, useEffect, useRef, useCallback } from 'react';
import { threatAPI } from '../api/client';

/* ─── Demo data constants ─────────────────────────────────────────── */
const DEMO_COUNTRIES = [
  'Russia', 'China', 'Nigeria', 'United States', 'Romania', 'Brazil',
  'India', 'Germany', 'Netherlands', 'Ukraine', 'Iran', 'North Korea',
  'Vietnam', 'Indonesia', 'Turkey', 'Pakistan', 'Bangladesh', 'Mexico',
];

const DEMO_ENTITIES = [
  'secure-login-verify.ru', 'paypa1-confirm.net', 'bank-alerts-update.xyz',
  'account-suspended.info', 'urgent-verify-id.com', 'fedex-delivery-hold.com',
  'amazon-refund-claim.net', 'microsoft-support-help.org', 'netfl1x-billing.com',
  'google-security-alert.ru', 'icloud-verify-now.xyz', 'crypto-rewards-2024.io',
  'wallet-recovery-help.net', 'visa-card-suspended.com', 'dhl-parcel-track.ru',
  '188.93.241.17', '45.142.212.100', '185.220.101.45', '103.21.244.0',
  'update-flash-player.com', 'login-secure-bank.xyz', 'prize-claim-now.net',
];

const DEMO_SCAN_TYPES = ['website', 'email', 'apk'];
const DEMO_RISK = [
  { level: 'High',   weight: 55, color: '#FF3B5C', icon: '⚠' },
  { level: 'Medium', weight: 30, color: '#FFB020', icon: '◈' },
  { level: 'Low',    weight: 15, color: '#3DDC84', icon: '✓' },
];

const DEMO_REASONS = {
  High: [
    'Phishing URL detected', 'Malicious APK permissions', 'Spoofed sender domain',
    'Known malware host', 'Credential harvesting page', 'Fake login portal',
    'High URL entropy + redirection chain', 'DMARC/SPF fail + urgency language',
  ],
  Medium: [
    'Suspicious redirect chain', 'No DMARC record', 'Self-signed SSL certificate',
    'Newly registered domain (< 30d)', 'Excessive permissions (APK)', 'Unverified sender',
  ],
  Low: [
    'Valid SSL · Domain age OK', 'SPF/DKIM/DMARC pass', 'No suspicious indicators',
    'Clean APK manifest', 'Trusted sender domain',
  ],
};

/* ─── Demo seed (starting events so the map never looks empty) ────── */
const SEED_EVENTS = Array.from({ length: 28 }, (_, i) => {
  const rnd = (arr) => arr[Math.floor(Math.random() * arr.length)];
  const riskItem = (() => {
    const r = Math.random() * 100;
    if (r < 55) return DEMO_RISK[0];
    if (r < 85) return DEMO_RISK[1];
    return DEMO_RISK[2];
  })();
  const country = rnd(DEMO_COUNTRIES);
  // Rough lat/lng per country name
  const GEO = {
    'Russia': [55.75, 37.62], 'China': [39.91, 116.39], 'Nigeria': [9.05, 7.49],
    'United States': [37.09, -95.71], 'Romania': [44.43, 26.10], 'Brazil': [-15.79, -47.88],
    'India': [20.59, 78.96], 'Germany': [51.16, 10.45], 'Netherlands': [52.13, 5.29],
    'Ukraine': [48.38, 31.17], 'Iran': [32.43, 53.69], 'North Korea': [40.34, 127.51],
    'Vietnam': [14.06, 108.28], 'Indonesia': [-0.79, 113.92], 'Turkey': [38.96, 35.24],
    'Pakistan': [30.37, 69.35], 'Bangladesh': [23.68, 90.35], 'Mexico': [23.63, -102.55],
  };
  const [lat, lng] = GEO[country] || [20, 80];
  return {
    id: `demo-seed-${i}`,
    entity: rnd(DEMO_ENTITIES),
    scan_type: rnd(DEMO_SCAN_TYPES),
    risk_level: riskItem.level,
    country,
    lat: lat + (Math.random() - 0.5) * 4,
    lng: lng + (Math.random() - 0.5) * 4,
    reason: rnd(DEMO_REASONS[riskItem.level]),
    _isDemo: true,
    timestamp: new Date(Date.now() - Math.random() * 3600_000 * 8).toISOString(),
  };
});

/* ─── Helpers ─────────────────────────────────────────────────────── */
function timeAgo(iso) {
  const diff = Math.floor((Date.now() - new Date(iso).getTime()) / 1000);
  if (diff < 60)  return `${diff}s ago`;
  if (diff < 3600) return `${Math.floor(diff/60)}m ago`;
  return `${Math.floor(diff/3600)}h ago`;
}

function riskColor(level) {
  if (level === 'High')   return '#FF3B5C';
  if (level === 'Medium') return '#FFB020';
  return '#3DDC84';
}

function riskIcon(level) {
  if (level === 'High')   return '⚠';
  if (level === 'Medium') return '◈';
  return '✓';
}

function pickWeighted() {
  const r = Math.random() * 100;
  if (r < 55) return DEMO_RISK[0];
  if (r < 85) return DEMO_RISK[1];
  return DEMO_RISK[2];
}

const rndFrom = (arr) => arr[Math.floor(Math.random() * arr.length)];

const GEO_MAP = {
  'Russia': [55.75,37.62],'China':[39.91,116.39],'Nigeria':[9.05,7.49],
  'United States':[37.09,-95.71],'Romania':[44.43,26.10],'Brazil':[-15.79,-47.88],
  'India':[20.59,78.96],'Germany':[51.16,10.45],'Netherlands':[52.13,5.29],
  'Ukraine':[48.38,31.17],'Iran':[32.43,53.69],'North Korea':[40.34,127.51],
  'Vietnam':[14.06,108.28],'Indonesia':[-0.79,113.92],'Turkey':[38.96,35.24],
  'Pakistan':[30.37,69.35],'Bangladesh':[23.68,90.35],'Mexico':[23.63,-102.55],
};

function makeEvent() {
  const riskItem = pickWeighted();
  const country  = rndFrom(DEMO_COUNTRIES);
  const [lat, lng] = GEO_MAP[country] || [20, 80];
  return {
    id: `demo-live-${Date.now()}-${Math.random()}`,
    entity: rndFrom(DEMO_ENTITIES),
    scan_type: rndFrom(DEMO_SCAN_TYPES),
    risk_level: riskItem.level,
    country,
    lat: lat + (Math.random()-0.5)*5,
    lng: lng + (Math.random()-0.5)*5,
    reason: rndFrom(DEMO_REASONS[riskItem.level]),
    _isDemo: true,
    timestamp: new Date().toISOString(),
  };
}

/* ─── Animated counter ────────────────────────────────────────────── */
function AnimatedCounter({ value, duration = 700 }) {
  const [displayed, setDisplayed] = useState(0);
  const rafRef  = useRef(null);
  const startRef = useRef(null);
  const fromRef  = useRef(0);

  useEffect(() => {
    const from = fromRef.current;
    const to   = value;
    if (from === to) return;
    if (rafRef.current) cancelAnimationFrame(rafRef.current);
    startRef.current = null;

    const step = (ts) => {
      if (!startRef.current) startRef.current = ts;
      const elapsed = ts - startRef.current;
      const progress = Math.min(elapsed / duration, 1);
      const eased = 1 - Math.pow(1 - progress, 3);
      setDisplayed(Math.round(from + (to - from) * eased));
      if (progress < 1) rafRef.current = requestAnimationFrame(step);
      else fromRef.current = to;
    };
    rafRef.current = requestAnimationFrame(step);
    return () => { if (rafRef.current) cancelAnimationFrame(rafRef.current); };
  }, [value, duration]);

  return <span className="tabular-nums">{displayed.toLocaleString()}</span>;
}

/* ─── Feed row ────────────────────────────────────────────────────── */
function FeedRow({ event, isNew, onSelectThreat }) {
  const reasonText = event.reason || (event.scan_type === 'website' ? 'Malicious URL' : event.scan_type === 'email' ? 'Phishing Email' : 'Suspicious APK');
  return (
    <div
      onClick={() => onSelectThreat?.(event)}
      title="Click to fly globe to this threat"
      className={`flex items-center justify-between gap-2 py-1.5 px-2 rounded cursor-pointer transition-all duration-200 ${
        isNew ? 'bg-cyan-500/15 border border-cyan-500/30' : 'hover:bg-white/[0.04] border border-transparent hover:border-white/10'
      }`}
      style={{ borderBottom: isNew ? undefined : '1px solid rgba(255,255,255,0.05)' }}
    >
      <div className="flex items-center gap-2 min-w-0 flex-1">
        <span
          className="text-xs font-bold flex-shrink-0"
          style={{ color: riskColor(event.risk_level) }}
        >
          {riskIcon(event.risk_level)}
        </span>
        <div className="min-w-0 flex-1 flex items-center gap-1.5 text-xs truncate">
          <span className="font-mono font-medium text-[#E6EDF3] truncate">
            {event.entity}
          </span>
          <span className="text-[#8B949E]/50">—</span>
          <span className="text-[#8B949E] truncate text-[11px]">
            {reasonText}
          </span>
          <span className="text-[#8B949E]/50">—</span>
          <span className="text-[#8B949E] text-[11px] flex-shrink-0">
            {event.country || 'Global'}
          </span>
        </div>
      </div>
      <div className="flex items-center gap-1.5 flex-shrink-0 ml-2">
        <span className="text-[10px] font-mono text-[#8B949E]">
          {timeAgo(event.timestamp)}
        </span>
        {event._isDemo && (
          <span className="text-[8px] font-mono px-1 rounded" style={{ background: 'rgba(255,176,32,0.12)', color: '#FFB020' }}>
            DEMO
          </span>
        )}
      </div>
    </div>
  );
}

/* ─── Main component ──────────────────────────────────────────────── */
export default function ThreatCounterPanel({ onEventsLoaded, onSelectThreat }) {
  const [stats, setStats] = useState({ threats_today: 247, high_risk_total: 1843, countries_flagged: 18 });
  const [events, setEvents] = useState(SEED_EVENTS);
  const [newEventId, setNewEventId] = useState(null);
  const [isDemo, setIsDemo] = useState(true);
  const [lastUpdated, setLastUpdated] = useState(new Date());
  const onEventsLoadedRef = useRef(onEventsLoaded);
  onEventsLoadedRef.current = onEventsLoaded;

  // Push seed events to globe immediately
  useEffect(() => {
    if (onEventsLoadedRef.current) onEventsLoadedRef.current(SEED_EVENTS);
  }, []);

  // Fetch real data
  const fetchAll = useCallback(async () => {
    try {
      const [statsRes, eventsRes] = await Promise.all([
        threatAPI.getStats(),
        threatAPI.getRecentEvents({ hours: 48, limit: 200 }),
      ]);
      const realEvents = eventsRes.data.events || [];
      const hasReal = realEvents.length > 0;

      if (hasReal) {
        setIsDemo(false);
        setStats(statsRes.data);
        setEvents(realEvents);
        if (onEventsLoadedRef.current) onEventsLoadedRef.current(realEvents);
      }
      // If real data is empty, keep demo stats/events as-is
      setLastUpdated(new Date());
    } catch (_) {
      /* backend not running — demo data continues */
    }
  }, []);

  useEffect(() => {
    fetchAll();
    const interval = setInterval(fetchAll, 20_000);
    return () => clearInterval(interval);
  }, [fetchAll]);

  // Auto-generate new demo events every 12–18 seconds (only in demo mode)
  useEffect(() => {
    const tick = () => {
      if (!isDemo) return;
      const ev = makeEvent();
      setNewEventId(ev.id);
      setEvents(prev => [ev, ...prev.slice(0, 49)]);
      setStats(prev => ({
        ...prev,
        threats_today:    prev.threats_today + 1,
        high_risk_total:  ev.risk_level === 'High' ? prev.high_risk_total + 1 : prev.high_risk_total,
        countries_flagged: prev.countries_flagged,
      }));
      setTimeout(() => setNewEventId(null), 800);
    };

    const schedule = () => {
      const delay = 12_000 + Math.random() * 6_000;
      return setTimeout(() => { tick(); timerId.current = schedule(); }, delay);
    };
    const timerId = { current: schedule() };
    return () => clearTimeout(timerId.current);
  }, [isDemo]);

  const feedEvents = events.slice(0, 8);
  const timeStr = lastUpdated.toLocaleTimeString('en-IN', { hour: '2-digit', minute: '2-digit', second: '2-digit' });

  return (
    <div className="flex flex-col h-full gap-4">
      {/* ── Header ────────────────────────────────────────── */}
      <div className="flex items-center justify-between">
        <div>
          <p className="section-label mb-0.5">Live Threat Feed</p>
          <h2 className="text-sm font-bold font-heading" style={{ color: 'var(--text-primary)', letterSpacing: '-0.01em' }}>
            QFIRENET SENSOR
          </h2>
        </div>
        <div className="flex items-center gap-1.5">
          <span className="live-dot" />
          <span className="text-[10px] font-mono font-semibold" style={{ color: 'var(--accent)' }}>LIVE</span>
        </div>
      </div>

      {/* ── Stat tiles ────────────────────────────────────── */}
      <div className="space-y-2.5">
        {/* Threats Today */}
        <div className="card p-4">
          <p className="section-label">THREATS TODAY</p>
          <div className="flex items-end justify-between">
            <span className="stat-number" style={{ color: '#FF3B5C' }}>
              <AnimatedCounter value={stats.threats_today || 0} />
            </span>
            <span className="text-[10px] font-mono pb-1" style={{ color: 'var(--text-muted)' }}>24H</span>
          </div>
        </div>

        <div className="grid grid-cols-2 gap-2.5">
          {/* High-risk total */}
          <div className="card p-3.5">
            <p className="section-label mb-1" style={{ fontSize: '10px' }}>HIGH-RISK</p>
            <span className="text-2xl font-bold font-heading tabular-nums" style={{ color: '#FFB020', letterSpacing: '-0.02em' }}>
              <AnimatedCounter value={stats.high_risk_total || 0} />
            </span>
            <p className="text-[9px] font-mono mt-1" style={{ color: 'var(--text-muted)' }}>ALL TIME</p>
          </div>
          {/* Countries */}
          <div className="card p-3.5">
            <p className="section-label mb-1" style={{ fontSize: '10px' }}>COUNTRIES</p>
            <span className="text-2xl font-bold font-heading tabular-nums" style={{ color: 'var(--accent)', letterSpacing: '-0.02em' }}>
              <AnimatedCounter value={stats.countries_flagged || 0} />
            </span>
            <p className="text-[9px] font-mono mt-1" style={{ color: 'var(--text-muted)' }}>LAST 48H</p>
          </div>
        </div>
      </div>

      {/* ── Live feed ──────────────────────────────────────── */}
      <div className="card p-3.5 flex-1">
        <div className="flex items-center justify-between mb-2">
          <p className="section-label mb-0">RECENT EVENTS</p>
          {isDemo && (
            <span className="text-[9px] font-mono px-1.5 py-0.5 rounded"
              style={{ background: 'rgba(255,176,32,0.10)', color: '#FFB020', border: '1px solid rgba(255,176,32,0.2)' }}>
              DEMO DATA
            </span>
          )}
        </div>
        <div className="overflow-hidden">
          {feedEvents.map((ev, i) => (
            <FeedRow
              key={ev.id}
              event={ev}
              isNew={ev.id === newEventId}
              onSelectThreat={onSelectThreat}
            />
          ))}
        </div>
      </div>

      {/* ── Footer ─────────────────────────────────────────── */}
      <p className="text-[9px] font-mono" style={{ color: 'var(--text-muted)' }}>
        {isDemo ? 'SIMULATED DATA · REAL SCANS TAKE PRIORITY' : 'LIVE SCAN DATA'} · {timeStr}
      </p>
    </div>
  );
}
