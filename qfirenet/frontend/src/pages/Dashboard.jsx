/**
 * pages/Dashboard.jsx — QFireNet Security Operations Dashboard
 *
 * Layout:
 *   1. Live Threat Globe Section (always populated — demo events immediately)
 *   2. Hero section with large heading + feature pills
 *   3. Scan Form section (independent, below the globe)
 *   4. Capability cards
 *
 * The globe section is fully independent of user scans — it shows
 * demo/real threat data automatically on page load.
 */

import { useState, useCallback, Suspense, lazy } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import ScanForm from '../components/ScanForm';
import ScanProgress from '../components/ScanProgress';
import ThreatCounterPanel from '../components/ThreatCounterPanel';
import { useAuth } from '../App';

const ThreatGlobe = lazy(() => import('../components/ThreatGlobe'));

const FEATURE_PILLS = [
  { icon: '🔒', text: 'SSL & TLS Analysis' },
  { icon: '🎣', text: 'Phishing Heuristics' },
  { icon: '✉️',  text: 'Email Auth Check' },
  { icon: '📱', text: 'APK Permissions' },
  { icon: '⚛️',  text: 'PQC Readiness' },
  { icon: '🤖', text: 'Groq AI Narration' },
  { icon: '📊', text: 'Shannon Entropy' },
  { icon: '🎯', text: 'Risk Tiering' },
];

const CAPABILITY_CARDS = [
  {
    color: 'var(--accent)',
    bgColor: 'var(--accent-dim)',
    borderColor: 'var(--accent-border)',
    icon: (
      <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
        <path strokeLinecap="round" strokeLinejoin="round"
          d="M12 21a9.004 9.004 0 008.716-6.747M12 21a9.004 9.004 0 01-8.716-6.747M12 21c2.485 0 4.5-4.03 4.5-9S14.485 3 12 3m0 18c-2.485 0-4.5-4.03-4.5-9S9.515 3 12 3m0 0a8.997 8.997 0 017.843 4.582M12 3a8.997 8.997 0 00-7.843 4.582m15.686 0A11.953 11.953 0 0112 10.5c-2.998 0-5.74-1.1-7.843-2.918m15.686 0A8.959 8.959 0 0121 12c0 .778-.099 1.533-.284 2.253m0 0A17.919 17.919 0 0112 16.5a17.92 17.92 0 01-8.716-2.247m0 0A9.015 9.015 0 013 12c0-1.605.42-3.113 1.157-4.418" />
      </svg>
    ),
    title: 'Website Scanner',
    desc: 'SSL cert validity, WHOIS domain age, phishing URL patterns, Shannon entropy, PQC readiness.',
    tags: ['SSL', 'WHOIS', 'PQC'],
  },
  {
    color: '#FFB020',
    bgColor: 'rgba(255,176,32,0.1)',
    borderColor: 'rgba(255,176,32,0.25)',
    icon: (
      <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
        <path strokeLinecap="round" strokeLinejoin="round"
          d="M21.75 6.75v10.5a2.25 2.25 0 01-2.25 2.25h-15a2.25 2.25 0 01-2.25-2.25V6.75m19.5 0A2.25 2.25 0 0019.5 4.5h-15a2.25 2.25 0 00-2.25 2.25m19.5 0v.243a2.25 2.25 0 01-1.07 1.916l-7.5 4.615a2.25 2.25 0 01-2.36 0L3.32 8.91a2.25 2.25 0 01-1.07-1.916V6.75" />
      </svg>
    ),
    title: 'Email Analyser',
    desc: 'SPF / DKIM / DMARC header auth, urgency language detection, credential phishing pattern match.',
    tags: ['SPF', 'DKIM', 'DMARC'],
  },
  {
    color: '#3DDC84',
    bgColor: 'rgba(61,220,132,0.08)',
    borderColor: 'rgba(61,220,132,0.2)',
    icon: (
      <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
        <path strokeLinecap="round" strokeLinejoin="round"
          d="M10.5 1.5H8.25A2.25 2.25 0 006 3.75v16.5a2.25 2.25 0 002.25 2.25h7.5A2.25 2.25 0 0018 20.25V3.75a2.25 2.25 0 00-2.25-2.25H13.5m-3 0V3h3V1.5m-3 0h3m-3 8.25h3m-3 4.5h3" />
      </svg>
    ),
    title: 'APK Inspector',
    desc: 'Static Android APK permission analysis. Risk tiers: Critical / High / Medium / Low.',
    tags: ['Androguard', 'Static Analysis'],
  },
];

function GlobeFallback() {
  return (
    <div className="flex flex-col items-center justify-center h-80 gap-3">
      <div className="w-8 h-8 rounded-full border-2 animate-spin"
        style={{ borderColor: 'var(--border)', borderTopColor: 'var(--accent)' }} />
      <p className="text-xs font-mono" style={{ color: 'var(--text-muted)' }}>
        Loading 3D globe...
      </p>
    </div>
  );
}

export default function Dashboard() {
  const { user } = useAuth();
  const navigate  = useNavigate();
  const [scanning, setScanning]     = useState(false);
  const [scanType, setScanType]     = useState('website');
  const [globeEvents, setGlobeEvents] = useState([]);
  const [focusedThreat, setFocusedThreat] = useState(null);

  const handleSelectThreat = useCallback((threat) => {
    setFocusedThreat(threat);
  }, []);

  const handleEventsLoaded = useCallback((events) => {
    setGlobeEvents(events);
  }, []);

  const handleStart  = (type)             => { setScanType(type); setScanning(true); };
  const handleResult = ({ data, scanType: type }) => {
    setScanning(false);
    const scanId = data.scan_id || data.id;
    navigate(scanId ? `/results/${scanId}` : '/dashboard', { state: { result: { ...data, scan_type: type } } });
  };
  const handleScanError = () => setScanning(false);

  return (
    <div style={{ background: 'var(--bg-base)' }}>

      {/* ── 1. Live Threat Map ─────────────────────────────────────────── */}
      <section className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 pt-8 pb-6">
        <div className="card overflow-hidden" style={{ background: 'var(--bg-card)' }}>

          {/* Header bar */}
          <div className="flex items-center justify-between px-5 py-3"
            style={{ borderBottom: '1px solid var(--border)' }}>
            <div className="flex items-center gap-2.5">
              <span className="live-dot" />
              <span className="section-label mb-0">Live Threat Activity Map</span>
            </div>
            <span className="text-xs font-mono" style={{ color: 'var(--text-muted)' }}>
              react-globe.gl · WebGL · Multi-Tier Semantic Zoom
            </span>
          </div>

          {/* Globe + Stats side-by-side */}
          <div className="grid grid-cols-1 lg:grid-cols-[1fr_360px]">
            {/* Globe */}
            <div className="relative flex items-center justify-center min-h-[480px] lg:min-h-[540px] w-full overflow-hidden"
              style={{ background: '#070B10' }}>
              <Suspense fallback={<GlobeFallback />}>
                <ThreatGlobe
                  events={globeEvents}
                  focusedEvent={focusedThreat}
                  onSelectThreat={handleSelectThreat}
                />
              </Suspense>
            </div>

            {/* Stats + Feed */}
            <div className="p-5 flex flex-col justify-between" style={{ borderLeft: '1px solid var(--border)', background: 'var(--bg-card)' }}>
              <ThreatCounterPanel
                onEventsLoaded={handleEventsLoaded}
                onSelectThreat={handleSelectThreat}
              />
            </div>
          </div>
        </div>
      </section>

      {/* ── 2. Hero ────────────────────────────────────────────────────── */}
      <section className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 py-12 text-center">

        {/* Badge */}
        <div className="inline-flex items-center gap-2 px-3 py-1.5 rounded-full mb-6"
          style={{ background: 'var(--accent-dim)', border: '1px solid var(--accent-border)' }}>
          <span className="live-dot" style={{ '--tw-ring-color': 'var(--accent)' }} />
          <span className="text-xs font-semibold" style={{ color: 'var(--accent)', fontFamily: 'Inter, sans-serif' }}>
            AI-Powered Threat Intelligence
          </span>
        </div>

        <h1
          style={{
            fontFamily: '"Space Grotesk", Inter, sans-serif',
            fontSize: 'clamp(2.25rem, 6vw, 4rem)',
            fontWeight: 800,
            lineHeight: 1.05,
            letterSpacing: '-0.035em',
            color: 'var(--text-primary)',
            marginBottom: '1.25rem',
          }}
        >
          Know Before<br />
          <span style={{ color: 'var(--accent)' }}>You Trust.</span>
        </h1>

        <p className="text-base max-w-xl mx-auto mb-8 leading-relaxed"
          style={{ color: 'var(--text-secondary)', fontFamily: 'Inter, sans-serif' }}>
          Evaluate websites, emails, and Android APKs for security risks in seconds.
          Powered by Groq + Llama 3.3 70B for plain-English threat explanations.
        </p>

        {/* Feature pills */}
        <div className="flex flex-wrap justify-center gap-2 mb-4">
          {FEATURE_PILLS.map((f) => (
            <span
              key={f.text}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-full text-xs font-medium transition-all duration-150"
              style={{
                background: 'var(--bg-card)',
                border: '1px solid var(--border)',
                color: 'var(--text-secondary)',
                fontFamily: 'Inter, sans-serif',
              }}
            >
              <span>{f.icon}</span>
              {f.text}
            </span>
          ))}
        </div>
      </section>

      {/* ── 3. Scan Form ───────────────────────────────────────────────── */}
      <section className="max-w-2xl mx-auto px-4 sm:px-6 pb-10">
        <div className="card" style={{ background: 'var(--bg-card)' }}>
          <div className="px-6 pt-5 pb-1">
            <h2 className="font-heading text-lg font-bold mb-0.5" style={{ color: 'var(--text-primary)' }}>
              Run a Threat Scan
            </h2>
            <p className="text-sm" style={{ color: 'var(--text-secondary)' }}>
              Paste a URL, an email, or upload an APK — results in under 30 seconds.
            </p>
          </div>

          <div className="px-6 pb-5 pt-4">
            <ScanForm onResult={handleResult} onStart={handleStart} onError={handleScanError} />

            {!user && (
              <div className="mt-3 flex items-center gap-2 px-4 py-3 rounded-lg"
                style={{ background: 'var(--bg-raised)', border: '1px solid var(--border)' }}>
                <svg className="w-4 h-4 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}
                  style={{ color: 'var(--text-muted)' }}>
                  <path strokeLinecap="round" strokeLinejoin="round"
                    d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                </svg>
                <p className="text-xs" style={{ color: 'var(--text-secondary)', fontFamily: 'Inter, sans-serif' }}>
                  Scanning without an account? Results won't be saved.{' '}
                  <Link to="/register" style={{ color: 'var(--accent)', fontWeight: 600 }}>
                    Register free →
                  </Link>
                </p>
              </div>
            )}
          </div>
        </div>

        {scanning && (
          <div className="mt-4">
            <ScanProgress scanType={scanType} isActive={scanning} />
          </div>
        )}
      </section>

      {/* ── 4. Capability Cards ────────────────────────────────────────── */}
      {!scanning && (
        <section className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 pb-16">
          <p className="section-label text-center mb-5">Supported Scan Types</p>

          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 mb-4">
            {CAPABILITY_CARDS.map((card) => (
              <div key={card.title} className="card p-5 group hover:border-opacity-50 transition-all duration-200"
                style={{ background: 'var(--bg-card)' }}>
                {/* Icon */}
                <div className="w-10 h-10 rounded-lg flex items-center justify-center mb-4"
                  style={{ background: card.bgColor, border: `1px solid ${card.borderColor}`, color: card.color }}>
                  {card.icon}
                </div>

                <h3 className="font-heading text-base font-bold mb-1.5" style={{ color: 'var(--text-primary)' }}>
                  {card.title}
                </h3>
                <p className="text-sm leading-relaxed mb-4" style={{ color: 'var(--text-secondary)', fontFamily: 'Inter, sans-serif' }}>
                  {card.desc}
                </p>
                <div className="flex flex-wrap gap-1.5">
                  {card.tags.map((tag) => (
                    <span key={tag} className="px-2 py-0.5 rounded text-xs font-mono font-medium"
                      style={{ background: card.bgColor, color: card.color, border: `1px solid ${card.borderColor}` }}>
                      {tag}
                    </span>
                  ))}
                </div>
              </div>
            ))}
          </div>

          {/* Groq AI banner */}
          <div className="card p-4 flex items-center gap-4" style={{ background: 'var(--bg-card)' }}>
            <div className="w-10 h-10 rounded-lg flex items-center justify-center flex-shrink-0"
              style={{ background: 'rgba(0,217,255,0.1)', border: '1px solid rgba(0,217,255,0.2)' }}>
              <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}
                style={{ color: 'var(--accent)' }}>
                <path strokeLinecap="round" strokeLinejoin="round"
                  d="M9.813 15.904L9 18.75l-.813-2.846a4.5 4.5 0 00-3.09-3.09L2.25 12l2.846-.813a4.5 4.5 0 003.09-3.09L9 5.25l.813 2.846a4.5 4.5 0 003.09 3.09L15.75 12l-2.846.813a4.5 4.5 0 00-3.09 3.09z" />
              </svg>
            </div>
            <div className="flex-1 min-w-0">
              <p className="font-heading text-sm font-bold mb-0.5" style={{ color: 'var(--text-primary)' }}>
                AI Narration on Every Scan
              </p>
              <p className="text-sm" style={{ color: 'var(--text-secondary)', fontFamily: 'Inter, sans-serif' }}>
                Groq + Llama 3.3 70B translates risk signals into plain-English explanations — automatically.
              </p>
            </div>
            <span className="flex-shrink-0 px-2.5 py-1 rounded text-xs font-semibold font-mono"
              style={{ background: 'rgba(0,217,255,0.1)', color: 'var(--accent)', border: '1px solid rgba(0,217,255,0.2)' }}>
              GROQ AI
            </span>
          </div>
        </section>
      )}
    </div>
  );
}
