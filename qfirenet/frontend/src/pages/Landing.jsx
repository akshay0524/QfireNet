/**
 * pages/Landing.jsx — QFireNet Hero Landing Page (Premium Redesign)
 */

import { useState, useEffect, useRef } from 'react';
import { Link } from 'react-router-dom';
import { statsAPI } from '../api/client';

/* ── Typewriter hook ─────────────────────────────────────────────────────── */
function useTypewriter(words, speed = 80, pause = 1800) {
  const [text, setText] = useState('');
  const [wordIdx, setWordIdx] = useState(0);
  const [deleting, setDeleting] = useState(false);

  useEffect(() => {
    const current = words[wordIdx % words.length];
    const timeout = setTimeout(() => {
      if (!deleting) {
        setText(current.slice(0, text.length + 1));
        if (text.length + 1 === current.length) {
          setTimeout(() => setDeleting(true), pause);
        }
      } else {
        setText(current.slice(0, text.length - 1));
        if (text.length === 0) {
          setDeleting(false);
          setWordIdx((i) => i + 1);
        }
      }
    }, deleting ? speed / 2 : speed);
    return () => clearTimeout(timeout);
  }, [text, deleting, wordIdx, words, speed, pause]);

  return text;
}

/* ── Animated counter ────────────────────────────────────────────────────── */
function useCounter(target, duration = 1600) {
  const [count, setCount] = useState(0);
  const ref = useRef(null);
  useEffect(() => {
    const observer = new IntersectionObserver(([entry]) => {
      if (!entry.isIntersecting) return;
      let start = 0;
      const step = target / (duration / 16);
      const timer = setInterval(() => {
        start = Math.min(start + step, target);
        setCount(Math.floor(start));
        if (start >= target) clearInterval(timer);
      }, 16);
      observer.disconnect();
    }, { threshold: 0.3 });
    if (ref.current) observer.observe(ref.current);
    return () => observer.disconnect();
  }, [target, duration]);
  return [count, ref];
}

const FEATURES = [
  {
    icon: (
      <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M12 21a9.004 9.004 0 008.716-6.747M12 21a9.004 9.004 0 01-8.716-6.747M12 21c2.485 0 4.5-4.03 4.5-9S14.485 3 12 3m0 18c-2.485 0-4.5-4.03-4.5-9S9.515 3 12 3m0 0a8.997 8.997 0 017.843 4.582M12 3a8.997 8.997 0 00-7.843 4.582" />
      </svg>
    ),
    title: 'URL & Website Scanner',
    desc: 'SSL validity, WHOIS domain age, phishing URL pattern detection, Shannon entropy analysis, and Post-Quantum Cryptography readiness assessment.',
    color: 'ocean',
    tag: 'Live',
    num: '01',
  },
  {
    icon: (
      <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M21.75 6.75v10.5a2.25 2.25 0 01-2.25 2.25h-15a2.25 2.25 0 01-2.25-2.25V6.75m19.5 0A2.25 2.25 0 0019.5 4.5h-15a2.25 2.25 0 00-2.25 2.25m19.5 0v.243a2.25 2.25 0 01-1.07 1.916l-7.5 4.615a2.25 2.25 0 01-2.36 0L3.32 8.91a2.25 2.25 0 01-1.07-1.916V6.75" />
      </svg>
    ),
    title: 'Email Fraud Detection',
    desc: 'Validates SPF, DKIM, and DMARC authentication headers. Detects sender domain spoofing, urgency-language patterns, and suspicious link density.',
    color: 'lavender',
    tag: 'Live',
    num: '02',
  },
  {
    icon: (
      <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M10.5 1.5H8.25A2.25 2.25 0 006 3.75v16.5a2.25 2.25 0 002.25 2.25h7.5A2.25 2.25 0 0018 20.25V3.75a2.25 2.25 0 00-2.25-2.25H13.5m-3 0V3h3V1.5m-3 0h3m-3 8.25h3m-3 3h3m-3 3h3" />
      </svg>
    ),
    title: 'APK Malware Inspector',
    desc: 'Static analysis of Android APK permissions via androguard. Maps each permission to Critical / High / Medium / Low risk tiers with volume penalty scoring.',
    color: 'peach',
    tag: 'Live',
    num: '03',
  },
  {
    icon: (
      <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M9.813 15.904L9 18.75l-.813-2.846a4.5 4.5 0 00-3.09-3.09L2.25 12l2.846-.813a4.5 4.5 0 003.09-3.09L9 5.25l.813 2.846a4.5 4.5 0 003.09 3.09L15.75 12l-2.846.813a4.5 4.5 0 00-3.09 3.09z" />
      </svg>
    ),
    title: 'AI-Powered Explanation',
    desc: 'Groq + Llama 3.3 70B translates raw signal data into plain-English explanations designed for non-technical users to understand risk at a glance.',
    color: 'ocean',
    tag: 'Groq AI',
    num: '04',
  },
  {
    icon: (
      <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M3.75 3v11.25A2.25 2.25 0 006 16.5h2.25M3.75 3h-1.5m1.5 0h16.5m0 0h1.5m-1.5 0v11.25A2.25 2.25 0 0118 16.5h-2.25m-7.5 0h7.5m-7.5 0l-1 3m8.5-3l1 3m0 0l.5 1.5m-.5-1.5h-9.5m0 0l-.5 1.5M9 11.25v1.5M12 9v3.75m3-6v6" />
      </svg>
    ),
    title: 'Trust Score Fusion',
    desc: 'Weighted aggregation formula converts individual signal scores into a single 0–100 Digital Trust Score — immediately actionable for any user.',
    color: 'lavender',
    tag: 'Research-Grade',
    num: '05',
  },
  {
    icon: (
      <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M7.864 4.243A7.5 7.5 0 0119.5 10.5c0 2.92-.556 5.709-1.568 8.268M5.742 6.364A7.465 7.465 0 004.5 10.5a7.464 7.464 0 01-1.15 3.993m1.989 3.559A11.209 11.209 0 008.25 10.5a3.75 3.75 0 117.5 0c0 .527-.021 1.049-.064 1.565M12 10.5a14.94 14.94 0 01-3.6 9.75m6.633-4.596a18.666 18.666 0 01-2.485 5.33" />
      </svg>
    ),
    title: 'PQC Readiness Check',
    desc: 'Checks whether websites support Post-Quantum Cryptography cipher suites (Kyber/ML-KEM), providing forward-looking security assessment.',
    color: 'peach',
    tag: 'Forward-Looking',
    num: '06',
  },
];

const COLOR_MAP = {
  ocean:    { bg: 'bg-ocean-500/15',    border: 'border-ocean-500/30',    text: 'text-ocean-300',    glow: '0 0 20px rgba(45,104,152,0.25)' },
  lavender: { bg: 'bg-lavender-500/15', border: 'border-lavender-500/30', text: 'text-lavender-300', glow: '0 0 20px rgba(158,123,158,0.25)' },
  peach:    { bg: 'bg-peach-500/15',    border: 'border-peach-500/30',    text: 'text-peach-300',    glow: '0 0 20px rgba(232,157,134,0.25)' },
};

const DEMO_SCORES = [
  { label: 'google.com',              score: 92, risk: 'Low',    color: '#4E9F76' },
  { label: 'phish-verify-login.tk',   score: 11, risk: 'High',   color: '#AD504F' },
  { label: 'my-bank-update.xyz',      score: 23, risk: 'High',   color: '#c05f5e' },
  { label: 'github.com',              score: 88, risk: 'Low',    color: '#4E9F76' },
];

const TYPEWRITER_WORDS = [
  'websites.',
  'email headers.',
  'Android APKs.',
  'phishing links.',
  'suspicious apps.',
];

function StatCard({ value, label, suffix = '', delay = 0 }) {
  return (
    <div className="text-center" style={{ animationDelay: `${delay}ms` }}>
      <div className="text-3xl sm:text-4xl font-extrabold text-gradient-peach tabular-nums font-heading stat-number">
        {value}{suffix}
      </div>
      <div className="text-xs mt-1.5 font-semibold tracking-wide" style={{ color: 'var(--text-secondary)' }}>{label}</div>
    </div>
  );
}

function AnimatedStatCard({ target, label, suffix = '', delay = 0 }) {
  const [count, ref] = useCounter(target, 1800);
  return (
    <div className="text-center" ref={ref} style={{ animationDelay: `${delay}ms` }}>
      <div className="text-3xl sm:text-4xl font-extrabold text-gradient-peach tabular-nums font-heading stat-number">
        {count.toLocaleString()}{suffix}
      </div>
      <div className="text-xs mt-1.5 font-semibold tracking-wide" style={{ color: 'var(--text-secondary)' }}>{label}</div>
    </div>
  );
}

function FeatureCard({ feature, index }) {
  const colors = COLOR_MAP[feature.color];
  return (
    <div
      className="glass-card card-shine p-6 hover-lift group border-lavender-500/15 relative"
      style={{ animationDelay: `${index * 80}ms` }}
    >
      {/* Number watermark */}
      <span className="absolute top-4 right-5 text-5xl font-black font-mono opacity-[0.04] select-none pointer-events-none">
        {feature.num}
      </span>

      <div className="flex items-start gap-4">
        <div
          className={`feature-icon-wrap flex-shrink-0 w-11 h-11 rounded-xl flex items-center justify-center
            ${colors.bg} border ${colors.border} ${colors.text}`}
          style={{ boxShadow: colors.glow }}
        >
          {feature.icon}
        </div>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-2">
            <h3 className="text-white font-bold text-base font-heading">{feature.title}</h3>
            <span className={`text-[11px] px-2 py-0.5 rounded-full border font-bold uppercase tracking-wider ${colors.bg} ${colors.border} ${colors.text}`}>
              {feature.tag}
            </span>
          </div>
          <p className="text-sm leading-relaxed" style={{ color: 'var(--text-secondary)' }}>{feature.desc}</p>
        </div>
      </div>
    </div>
  );
}

export default function Landing() {
  const [stats, setStats] = useState(null);
  const typeText = useTypewriter(TYPEWRITER_WORDS, 75, 2000);
  const [activeDemoIdx, setActiveDemoIdx] = useState(0);

  useEffect(() => {
    statsAPI.getStats()
      .then(res => setStats(res.data))
      .catch(() => {});
  }, []);

  useEffect(() => {
    const t = setInterval(() => setActiveDemoIdx(i => (i + 1) % DEMO_SCORES.length), 2200);
    return () => clearInterval(t);
  }, []);

  return (
    <div className="relative overflow-hidden">
      {/* Background decorations */}
      <div className="absolute inset-0 grid-bg opacity-60 pointer-events-none" />
      <div className="absolute orb orb-blue  w-[700px] h-[420px] -top-28 -left-32  animate-float pointer-events-none"         />
      <div className="absolute orb orb-violet w-[550px] h-[400px] top-1/3 -right-28  animate-float-delayed pointer-events-none" />
      <div className="absolute orb orb-cyan  w-[440px] h-[340px] bottom-1/4 left-1/4 animate-float-slow pointer-events-none"  />

      <div className="relative max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">

        {/* ── Hero Section ──────────────────────────────────────────── */}
        <div className="pt-10 sm:pt-14 pb-16 text-center">

          {/* Live badge */}
          <div className="inline-flex items-center gap-2.5 px-4 py-2 rounded-full
            border border-peach-500/35 bg-peach-500/12 text-peach-300
            text-xs font-bold mb-6 sm:mb-8 shadow-glow-peach tracking-wide uppercase">
            <span className="relative flex h-2 w-2">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-peach-400 opacity-75" />
              <span className="relative inline-flex rounded-full h-2 w-2 bg-peach-400" />
            </span>
            AI-Powered Cyber Threat Assessment
          </div>

          {/* Headline */}
          <h1 className="text-5xl sm:text-6xl lg:text-7xl font-extrabold text-white mb-6 leading-tight tracking-tight font-heading animate-rise-up">
            <span className="text-gradient">Know Before</span>
            <br />
            <span>You Trust.</span>
          </h1>

          {/* Typewriter sub-headline */}
          <div className="flex items-center justify-center gap-2 mb-8">
            <p className="text-slate-300 text-lg sm:text-xl font-normal leading-relaxed">
              Instantly evaluate{' '}
              <span
                className="text-peach-300 font-bold font-mono inline-block min-w-[200px] text-left"
                aria-live="polite"
              >
                {typeText}
                <span className="animate-blink text-ocean-400">|</span>
              </span>
            </p>
          </div>

          <p className="text-slate-400 text-base max-w-2xl mx-auto mb-12 leading-relaxed">
            QFireNet delivers explainable AI trust scores in{' '}
            <span className="text-peach-300 font-semibold">seconds</span>
            {' '}— designed for security professionals and everyday users alike.
          </p>

          {/* CTAs */}
          <div className="flex flex-col sm:flex-row items-center justify-center gap-4 mb-20">
            <Link to="/dashboard" className="btn-primary px-9 py-4 text-base font-bold shadow-glow-ocean">
              <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z" />
              </svg>
              Try Free Scan
            </Link>
            <Link to="/register" className="btn-secondary px-9 py-4 text-base font-bold">
              <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M15.75 6a3.75 3.75 0 11-7.5 0 3.75 3.75 0 017.5 0zM4.501 20.118a7.5 7.5 0 0114.998 0A17.933 17.933 0 0112 21.75c-2.676 0-5.216-.584-7.499-1.632z" />
              </svg>
              Sign Up Free
            </Link>
          </div>

          {/* Stats row */}
          <div className="inline-grid grid-cols-2 sm:grid-cols-4 gap-8 sm:gap-14 px-10 py-7
            glass-card border-lavender-500/20 animate-scale-in">
            {stats ? (
              <>
                <AnimatedStatCard target={stats.total_scans}      label="Total Scans"        suffix="+" delay={0}   />
                <AnimatedStatCard target={stats.avg_trust_score}  label="Avg Trust Score"    suffix="/100" delay={100} />
                <AnimatedStatCard target={stats.high_risk_count}  label="Threats Identified" delay={200} />
                <StatCard         value="< 3s"                    label="Avg Response Time"  delay={300} />
              </>
            ) : (
              <>
                <StatCard value="10K"  label="Total Scans"        suffix="+" />
                <StatCard value="72.4" label="Avg Trust Score"    suffix="/100" />
                <StatCard value="2.1K" label="Threats Identified" />
                <StatCard value="< 3s" label="Avg Response Time"  />
              </>
            )}
          </div>
        </div>

        {/* ── Live Demo Preview ─────────────────────────────────────── */}
        <div className="mb-24">
          <p className="text-center text-[12px] font-bold uppercase tracking-widest mb-6" style={{ color: 'var(--text-muted)' }}>
            Live Signal Evaluations — Sample Outputs
          </p>
          <div className="relative max-w-4xl mx-auto">
            {/* Scanning overlay strip */}
            <div className="scan-container rounded-2xl overflow-visible">
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                {DEMO_SCORES.map(({ label, score, risk, color }, idx) => {
                  const isActive = idx === activeDemoIdx;
                  return (
                    <div
                      key={label}
                      className={`glass-card p-4 flex flex-col items-center gap-3 transition-all duration-500 ${
                        isActive
                          ? 'border-peach-500/40 scale-105 shadow-glow-peach'
                          : 'border-lavender-500/15 opacity-70'
                      }`}
                      style={isActive ? { boxShadow: `0 0 30px ${color}30` } : {}}
                    >
                      {/* Donut score */}
                      <div className="relative w-16 h-16">
                        <svg className="w-full h-full -rotate-90" viewBox="0 0 36 36">
                          <circle cx="18" cy="18" r="15" fill="none" stroke="rgba(255,255,255,0.06)" strokeWidth="3" />
                          <circle
                            cx="18" cy="18" r="15" fill="none"
                            stroke={color} strokeWidth="3" strokeLinecap="round"
                            strokeDasharray={`${(score / 100) * 94.2} 94.2`}
                            style={{ transition: 'all 0.5s ease' }}
                          />
                        </svg>
                        <span
                          className="absolute inset-0 flex items-center justify-center text-sm font-black font-mono"
                          style={{ color }}
                        >
                          {score}
                        </span>
                      </div>
                      <div className="text-center">
                        <p className="text-[12px] font-mono truncate max-w-[100px]" style={{ color: 'var(--text-primary)' }}>{label}</p>
                        <p className="text-[11px] mt-0.5 font-bold uppercase tracking-widest" style={{ color }}>
                          {risk} Risk
                        </p>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          </div>
        </div>

        {/* ── Features Grid ─────────────────────────────────────────── */}
        <div className="mb-24">
          <div className="text-center mb-12">
            <div className="tag-frosted inline-flex mb-4">
              <span className="w-1.5 h-1.5 rounded-full bg-ocean-400 animate-pulse mr-1" />
              Six Intelligence Engines
            </div>
            <h2 className="text-3xl sm:text-4xl font-extrabold text-white mb-4 font-heading">
              Six signal engines,{' '}
              <span className="text-gradient">one trust score</span>
            </h2>
            <p className="max-w-xl mx-auto text-base leading-relaxed" style={{ color: 'var(--text-secondary)' }}>
              Multi-dimensional feature extraction feeds into a transparent scoring matrix with Groq AI narration.
            </p>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {FEATURES.map((f, i) => (
              <FeatureCard key={f.title} feature={f} index={i} />
            ))}
          </div>
        </div>

        {/* ── How It Works ──────────────────────────────────────────── */}
        <div className="mb-24">
          <div className="text-center mb-12">
            <div className="tag-frosted inline-flex mb-4">Process</div>
            <h2 className="text-3xl font-extrabold text-white mb-3 font-heading">
              Evaluation <span className="text-gradient-peach">workflow</span>
            </h2>
            <p className="text-sm max-w-md mx-auto" style={{ color: 'var(--text-secondary)' }}>
              From raw input to plain-English risk report in under 3 seconds.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-4 gap-6 relative">
            {/* Connector line (desktop) */}
            <div className="absolute top-10 left-[calc(12.5%+1.5rem)] right-[calc(12.5%+1.5rem)]
              h-px bg-gradient-to-r from-transparent via-peach-500/40 to-transparent hidden md:block" />

            {[
              { step: '01', title: 'Submit Input',       desc: 'Provide a URL, raw email headers, or upload an APK file.',     icon: '📤', color: 'text-ocean-300' },
              { step: '02', title: 'Feature Extraction', desc: 'Parallel modules run security heuristics and signal checks.',   icon: '🔍', color: 'text-lavender-300' },
              { step: '03', title: 'Score Fusion',       desc: 'Weighted scoring matrix calculates the 0–100 trust score.',    icon: '📊', color: 'text-peach-300' },
              { step: '04', title: 'AI Narration',       desc: 'Groq + Llama 3.3 70B writes the plain-English risk report.',   icon: '🤖', color: 'text-ocean-300' },
            ].map(({ step, title, desc, icon, color }) => (
              <div key={step} className="text-center relative group">
                <div className="w-20 h-20 rounded-2xl mx-auto mb-5 flex items-center justify-center text-3xl
                  bg-dusk-800 border border-white/8 transition-all duration-300
                  group-hover:border-peach-500/40 group-hover:shadow-glow-peach group-hover:scale-105">
                  {icon}
                </div>
                <p className={`text-xs font-mono font-black mb-1.5 ${color}`}>{step}</p>
                <h3 className="text-white font-bold mb-2 font-heading text-base">{title}</h3>
                <p className="text-sm leading-relaxed" style={{ color: 'var(--text-secondary)' }}>{desc}</p>
              </div>
            ))}
          </div>
        </div>

        {/* ── Tech Stack Logos ──────────────────────────────────────── */}
        <div className="mb-24">
          <p className="text-center text-[12px] font-bold uppercase tracking-widest mb-8" style={{ color: 'var(--text-muted)' }}>
            Powered by
          </p>
          <div className="flex flex-wrap justify-center items-center gap-6 opacity-50">
            {[
              { name: 'FastAPI',     color: '#009688' },
              { name: 'React',       color: '#61DAFB' },
              { name: 'Groq',        color: '#f0b19d' },
              { name: 'Llama 3.3',   color: '#9e7b9e' },
              { name: 'PostgreSQL',  color: '#336791' },
              { name: 'androguard', color: '#4CAF50' },
            ].map(({ name, color }) => (
              <div
                key={name}
                className="px-4 py-2 rounded-lg border border-white/8 text-xs font-bold font-mono"
                style={{ color, borderColor: `${color}25` }}
              >
                {name}
              </div>
            ))}
          </div>
        </div>

        {/* ── CTA Banner ────────────────────────────────────────────── */}
        <div className="mb-24">
          <div className="glass-card card-shine p-12 text-center relative overflow-hidden border-ocean-500/30"
            style={{ background: 'rgba(14, 25, 42, 0.85)' }}>
            {/* Background orbs inside CTA */}
            <div className="absolute orb orb-blue   w-64 h-64 -top-20 -left-20  opacity-25 pointer-events-none" />
            <div className="absolute orb orb-violet w-48 h-48 -bottom-16 -right-16 opacity-20 pointer-events-none" />

            <div className="relative">
              {/* Top badge */}
              <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full
                border border-peach-500/30 bg-peach-500/10 text-peach-300
                text-[10px] font-bold uppercase tracking-wider mb-6">
                <span className="w-1.5 h-1.5 rounded-full bg-peach-400 animate-pulse" />
                No signup required
              </div>

              <h2 className="text-3xl sm:text-4xl font-extrabold text-white mb-4 font-heading">
                Ready to assess your digital{' '}
                <span className="text-gradient">trust</span>?
              </h2>
              <p className="mb-10 max-w-lg mx-auto text-base leading-relaxed" style={{ color: 'var(--text-secondary)' }}>
                Instant scans with zero setup required. Create a free account to save and compare scan history over time.
              </p>
              <div className="flex flex-col sm:flex-row gap-4 justify-center">
                <Link to="/dashboard" className="btn-primary px-10 py-4 text-base font-bold">
                  Start Scanning Free
                </Link>
                <Link to="/register" className="btn-secondary px-10 py-4 text-base font-bold">
                  Create Free Account
                </Link>
              </div>
            </div>
          </div>
        </div>

      </div>
    </div>
  );
}
