/**
 * components/PQCBadge.jsx — Post-Quantum Cryptography readiness badge.
 *
 * A standalone badge component that visually indicates whether the scanned
 * site uses post-quantum or hybrid cipher suites.
 *
 * Honest framing: most sites today will NOT pass PQC checks —
 * that is expected and correct.  We show this as informational/future-facing,
 * not as a failure.
 */

export default function PQCBadge({ pqcResult }) {
  if (!pqcResult) return null;

  const isReady = pqcResult.pqc_ready;
  const cipher  = pqcResult.cipher_suite || 'Unknown';
  const note    = pqcResult.note || '';
  const tls     = pqcResult.tls_version || '';

  return (
    <div className="glass-card p-5 animate-fade-in">
      <h3 className="section-title">Post-Quantum Cryptography</h3>

      <div className="flex items-start gap-4">
        {/* Icon */}
        <div
          className={`w-12 h-12 rounded-xl flex items-center justify-center flex-shrink-0 ${
            isReady ? 'bg-blue-500/20' : 'bg-slate-700/40'
          }`}
        >
          <svg
            className={`w-6 h-6 ${isReady ? 'text-blue-400' : 'text-slate-500'}`}
            fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}
          >
            <path strokeLinecap="round" strokeLinejoin="round"
              d="M15.75 5.25a3 3 0 013 3m3 0a6 6 0 01-7.029 5.912c-.563-.097-1.159.026-1.563.43L10.5 17.25H8.25v2.25H6v2.25H2.25v-2.818c0-.597.237-1.17.659-1.591l6.499-6.499c.404-.404.527-1 .43-1.563A6 6 0 1121.75 8.25z" />
          </svg>
        </div>

        {/* Content */}
        <div className="flex-1 min-w-0">
          {/* Status */}
          <div className="flex items-center gap-2 mb-2">
            <span
              className={`inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-bold border ${
                isReady
                  ? 'bg-blue-500/15 text-blue-400 border-blue-500/30'
                  : 'bg-slate-700/40 text-slate-400 border-slate-600/30'
              }`}
            >
              {isReady ? '✓ PQC Ready' : '· Classical TLS Only'}
            </span>
            {tls && (
              <span className="text-xs text-slate-600 font-mono">{tls}</span>
            )}
          </div>

          {/* Cipher */}
          {cipher && cipher !== 'Unknown' && (
            <p className="text-slate-400 text-xs font-mono truncate mb-1">
              Cipher: <span className="text-slate-300">{cipher}</span>
            </p>
          )}

          {/* Explanatory note */}
          <p className="text-slate-500 text-xs leading-relaxed">
            {isReady
              ? 'This site uses a hybrid post-quantum cipher, offering protection against future quantum computers.'
              : 'This site uses standard TLS — which is the industry norm today. PQC adoption is still in its early stages globally. This is informational, not a security failure.'}
          </p>

          {/* What is PQC? tooltip */}
          <details className="mt-2">
            <summary className="text-electric-500/70 text-xs cursor-pointer hover:text-electric-400 transition-colors">
              What is Post-Quantum Cryptography?
            </summary>
            <p className="text-slate-500 text-xs mt-1 leading-relaxed">
              Today's encryption (RSA, ECC) can be broken by sufficiently powerful quantum computers —
              which don't exist yet, but are being developed. PQC uses mathematical algorithms that
              remain secure even against quantum attacks. NIST standardised several PQC algorithms
              in 2024 (CRYSTALS-Kyber/ML-KEM for key exchange).
            </p>
          </details>
        </div>
      </div>
    </div>
  );
}
