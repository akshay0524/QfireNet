/**
 * components/ScanProgress.jsx — Animated Real-Time Scan Step Indicator
 *
 * Shows a live step-by-step progress display during a scan
 * using sunset sky palette & Plus Jakarta Sans typography.
 */

import { useState, useEffect } from 'react';

const SCAN_STEPS = {
  website: [
    { id: 'init',     label: 'Initializing security scan', icon: '🔍', ms: 200  },
    { id: 'ssl',      label: 'Checking SSL certificate',    icon: '🔒', ms: 1200 },
    { id: 'whois',    label: 'Running WHOIS lookup',         icon: '🌐', ms: 2500 },
    { id: 'phishing', label: 'Analyzing URL heuristics',   icon: '🎣', ms: 1000 },
    { id: 'pqc',      label: 'Checking PQC readiness',       icon: '⚛️', ms: 800  },
    { id: 'ai',       label: 'Generating AI explanation',    icon: '🤖', ms: 3000 },
    { id: 'done',     label: 'Finalizing report',            icon: '✅', ms: 300  },
  ],
  email: [
    { id: 'init',    label: 'Initializing scan',           icon: '🔍', ms: 200  },
    { id: 'headers', label: 'Parsing email headers',       icon: '📧', ms: 800  },
    { id: 'spf',     label: 'Verifying SPF / DKIM / DMARC', icon: '🔐', ms: 1200 },
    { id: 'content', label: 'Scanning email body',         icon: '📝', ms: 1000 },
    { id: 'ai',      label: 'Generating AI explanation',   icon: '🤖', ms: 3000 },
    { id: 'done',    label: 'Finalizing report',           icon: '✅', ms: 300  },
  ],
  apk: [
    { id: 'init',        label: 'Initializing scan',          icon: '🔍', ms: 200  },
    { id: 'extract',     label: 'Extracting APK manifest',    icon: '📦', ms: 1500 },
    { id: 'permissions', label: 'Mapping permission risks',   icon: '🔑', ms: 2000 },
    { id: 'metadata',    label: 'Scoring app metadata',       icon: '📱', ms: 800  },
    { id: 'ai',          label: 'Generating AI explanation',  icon: '🤖', ms: 3000 },
    { id: 'done',        label: 'Finalizing report',          icon: '✅', ms: 300  },
  ],
};

export default function ScanProgress({ scanType = 'website', isActive }) {
  const [currentStep, setCurrentStep] = useState(0);
  const steps = SCAN_STEPS[scanType] || SCAN_STEPS.website;

  useEffect(() => {
    if (!isActive) {
      setCurrentStep(0);
      return;
    }

    let totalDelay = 0;
    const timers = [];

    steps.forEach((step, i) => {
      const t = setTimeout(() => {
        setCurrentStep(i);
      }, totalDelay);
      timers.push(t);
      totalDelay += step.ms;
    });

    return () => timers.forEach(clearTimeout);
  }, [isActive, scanType]);

  if (!isActive) return null;

  return (
    <div className="glass-card p-5 animate-fade-in border-ocean-500/20">
      {/* Header */}
      <div className="flex items-center gap-3 mb-5">
        <div className="relative">
          <div className="w-8 h-8 rounded-lg bg-ocean-500/20 flex items-center justify-center border border-ocean-500/30">
            <svg className="w-4 h-4 text-ocean-300 animate-spin-slow" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z" />
            </svg>
          </div>
        </div>
        <div>
          <p className="text-white text-sm font-semibold">Threat scan in progress</p>
          <p className="text-slate-400 text-xs">Running multi-vector analysis...</p>
        </div>
      </div>

      {/* Steps */}
      <div className="space-y-2.5">
        {steps.map((step, i) => {
          const isDone    = i < currentStep;
          const isActive  = i === currentStep;

          return (
            <div
              key={step.id}
              className={`flex items-center gap-3 px-3 py-2 rounded-lg transition-all duration-300 ${
                isActive  ? 'bg-ocean-500/10 border border-ocean-400/30' :
                isDone    ? 'opacity-65' :
                'opacity-30'
              }`}
            >
              {/* Step dot */}
              <div className="flex-shrink-0">
                {isDone ? (
                  <div className="w-2.5 h-2.5 rounded-full bg-emerald-400" />
                ) : isActive ? (
                  <div className="w-2.5 h-2.5 rounded-full bg-peach-400 animate-pulse shadow-sm shadow-peach-400" />
                ) : (
                  <div className="w-2.5 h-2.5 rounded-full bg-dusk-700 border border-white/10" />
                )}
              </div>

              {/* Icon */}
              <span className="text-base leading-none">{step.icon}</span>

              {/* Label */}
              <span className={`text-xs font-medium flex-1 ${
                isActive ? 'text-slate-100 font-semibold' : isDone ? 'text-slate-300' : 'text-slate-500'
              }`}>
                {step.label}
              </span>

              {/* Status indicator */}
              {isDone && (
                <svg className="w-3.5 h-3.5 text-emerald-400 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.5}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M4.5 12.75l6 6 9-13.5" />
                </svg>
              )}
              {isActive && (
                <div className="flex gap-0.5 flex-shrink-0">
                  {[0, 1, 2].map(j => (
                    <div key={j} className="w-1 h-1 rounded-full bg-peach-400 animate-bounce"
                      style={{ animationDelay: `${j * 100}ms` }} />
                  ))}
                </div>
              )}
            </div>
          );
        })}
      </div>

      {/* Progress bar */}
      <div className="mt-4 h-1.5 bg-dusk-900 rounded-full overflow-hidden border border-white/5">
        <div
          className="h-full rounded-full bg-gradient-to-r from-ocean-500 via-lavender-500 to-peach-500 transition-all duration-500"
          style={{ width: `${Math.round((currentStep / (steps.length - 1)) * 100)}%` }}
        />
      </div>
    </div>
  );
}
