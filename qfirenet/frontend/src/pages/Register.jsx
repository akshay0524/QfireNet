/**
 * pages/Register.jsx — Nothing OS Registration Page
 *
 * True black, dot-matrix grid, Space Mono, hairline borders.
 * Password strength: monochrome bar segments.
 */

import { useState, useEffect } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { authAPI, tokenHelper } from '../api/client';
import { useAuth } from '../App';

function PasswordStrength({ password }) {
  const checks = [
    { label: '8+ CHARS',   pass: password.length >= 8 },
    { label: 'UPPERCASE',  pass: /[A-Z]/.test(password) },
    { label: 'NUM/SYMBOL', pass: /[0-9!@#$%^&*]/.test(password) },
  ];
  const score = checks.filter(c => c.pass).length;
  const barColors = ['', '#FF0000', '#888888', '#ffffff'];
  const labels    = ['', 'WEAK', 'FAIR', 'STRONG'];
  const textColors = ['', 'text-red-500', 'text-gray-400', 'text-white'];

  if (!password) return null;

  return (
    <div className="mt-2 space-y-1.5 animate-fade-in">
      {/* Strength segments */}
      <div className="flex gap-1 h-[2px]">
        {[1, 2, 3].map((i) => (
          <div
            key={i}
            className="flex-1 transition-all duration-150"
            style={{ backgroundColor: score >= i ? barColors[score] : 'rgba(255,255,255,0.08)' }}
          />
        ))}
      </div>
      <div className="flex items-center justify-between">
        <div className="flex flex-wrap gap-x-3 gap-y-0.5">
          {checks.map((c) => (
            <span key={c.label} className={`text-[9px] font-mono flex items-center gap-1 transition-colors duration-150 ${
              c.pass ? 'text-white/60' : 'text-white/15'
            }`}>
              {c.pass ? '◆' : '◇'} {c.label}
            </span>
          ))}
        </div>
        {score > 0 && (
          <span className={`text-[9px] font-mono font-bold ${textColors[score]}`}>
            {labels[score]}
          </span>
        )}
      </div>
    </div>
  );
}

function InputField({ id, type, label, placeholder, value, onChange, icon, hint, autoFocus, autoComplete, children }) {
  const [focused, setFocused] = useState(false);
  return (
    <div>
      <label
        htmlFor={id}
        className="block text-[10px] font-mono font-bold mb-2 uppercase tracking-[0.18em] text-white/40"
      >
        {label}
      </label>
      <div className="relative">
        <div className={`absolute left-3 top-1/2 -translate-y-1/2 transition-colors duration-150 ${
          focused ? 'text-white/60' : 'text-white/20'
        }`}>
          {icon}
        </div>
        <input
          id={id}
          type={type}
          value={value}
          onChange={onChange}
          onFocus={() => setFocused(true)}
          onBlur={() => setFocused(false)}
          placeholder={placeholder}
          autoFocus={autoFocus}
          autoComplete={autoComplete}
          required
          className="input-field pl-9"
          style={{ borderColor: focused ? 'rgba(255,255,255,0.7)' : undefined }}
        />
      </div>
      {hint && <p className="mt-1.5 text-[9px] font-mono text-white/20 uppercase tracking-wide">{hint}</p>}
      {children}
    </div>
  );
}

export default function Register() {
  const { login }   = useAuth();
  const navigate    = useNavigate();
  const [email, setEmail]           = useState('');
  const [password, setPassword]     = useState('');
  const [confirm, setConfirm]       = useState('');
  const [error, setError]           = useState('');
  const [fieldErrors, setFieldErrors] = useState({});
  const [loading, setLoading]       = useState(false);
  const [mounted, setMounted]       = useState(false);
  const [success, setSuccess]       = useState(false);

  useEffect(() => { setTimeout(() => setMounted(true), 60); }, []);

  const validate = () => {
    const errs = {};
    if (!email.trim()) errs.email = 'EMAIL REQUIRED';
    if (password.length < 8) errs.password = 'MIN 8 CHARACTERS';
    if (password !== confirm) errs.confirm = 'PASSWORDS DO NOT MATCH';
    setFieldErrors(errs);
    return Object.keys(errs).length === 0;
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    if (!validate()) return;
    setLoading(true);
    try {
      const res = await authAPI.register(email, password);
      const { access_token, user } = res.data;
      tokenHelper.save(access_token, user);
      login(user);
      setSuccess(true);
      setTimeout(() => navigate('/dashboard'), 800);
    } catch (err) {
      const detail = err.response?.data?.detail;
      setError(
        typeof detail === 'string'
          ? detail.toUpperCase()
          : Array.isArray(detail)
          ? detail.map(d => d.msg).join(' · ').toUpperCase()
          : 'REGISTRATION FAILED. TRY AGAIN.'
      );
    } finally {
      setLoading(false);
    }
  };

  const iconEmail = (
    <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
      <path strokeLinecap="round" strokeLinejoin="round"
        d="M21.75 6.75v10.5a2.25 2.25 0 01-2.25 2.25h-15a2.25 2.25 0 01-2.25-2.25V6.75m19.5 0A2.25 2.25 0 0019.5 4.5h-15a2.25 2.25 0 00-2.25 2.25m19.5 0v.243a2.25 2.25 0 01-1.07 1.916l-7.5 4.615a2.25 2.25 0 01-2.36 0L3.32 8.91a2.25 2.25 0 01-1.07-1.916V6.75" />
    </svg>
  );
  const iconLock = (
    <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
      <path strokeLinecap="round" strokeLinejoin="round"
        d="M16.5 10.5V6.75a4.5 4.5 0 10-9 0v3.75m-.75 11.25h10.5a2.25 2.25 0 002.25-2.25v-6.75a2.25 2.25 0 00-2.25-2.25H6.75a2.25 2.25 0 00-2.25 2.25v6.75a2.25 2.25 0 002.25 2.25z" />
    </svg>
  );

  return (
    <div className="min-h-[calc(100vh-58px)] flex items-center justify-center px-4 relative overflow-hidden bg-black">

      {/* Dot-matrix background */}
      <div className="absolute inset-0 dot-matrix-bg opacity-25 pointer-events-none" />
      <div className="absolute inset-0 scan-container pointer-events-none" />

      <div
        className="relative w-full max-w-sm transition-all duration-200"
        style={{ opacity: mounted ? 1 : 0, transform: mounted ? 'translateY(0)' : 'translateY(16px)' }}
      >
        {/* Header */}
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center w-12 h-12 border border-white/15 mb-5"
            style={{ borderRadius: '2px' }}>
            <svg className="w-6 h-6 text-white/70" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round"
                d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z" />
            </svg>
          </div>
          <h1 className="text-xl font-mono font-bold text-white uppercase tracking-widest mb-1">
            CREATE ACCOUNT
          </h1>
          <p className="text-white/30 text-[10px] font-mono uppercase tracking-widest">
            FREE · SAVE SCAN HISTORY
          </p>
        </div>

        {/* Card */}
        <div
          className="nm-card p-7 relative overflow-hidden"
          style={{ borderColor: success ? 'rgba(255,255,255,0.35)' : undefined }}
        >
          {/* Success overlay */}
          {success && (
            <div className="absolute inset-0 flex items-center justify-center z-10 bg-black">
              <div className="text-center animate-fade-in">
                <div className="w-12 h-12 border border-white/30 flex items-center justify-center mx-auto mb-3"
                  style={{ borderRadius: '2px' }}>
                  <svg className="w-6 h-6 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.5}>
                    <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
                  </svg>
                </div>
                <p className="text-white font-mono font-bold text-xs uppercase tracking-widest">ACCOUNT CREATED</p>
                <p className="text-white/30 text-[10px] font-mono mt-1 uppercase">REDIRECTING...</p>
              </div>
            </div>
          )}

          {/* Global error */}
          {error && (
            <div className="mb-4 px-3 py-2.5 border border-red-500/40 bg-red-500/5 flex items-start gap-2.5 animate-fade-in"
              style={{ borderRadius: '2px' }}>
              <span className="text-red-500 text-[10px] font-mono mt-0.5 flex-shrink-0">✕</span>
              <span className="text-red-400 text-xs font-mono">{error}</span>
            </div>
          )}

          <form onSubmit={handleSubmit} className="space-y-4">
            <InputField
              id="reg-email"
              type="email"
              label="Email Address"
              placeholder="user@example.com"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              icon={iconEmail}
              autoFocus
              autoComplete="email"
            >
              {fieldErrors.email && (
                <p className="mt-1 text-[9px] font-mono text-red-500 uppercase">{fieldErrors.email}</p>
              )}
            </InputField>

            <InputField
              id="reg-password"
              type="password"
              label="Password"
              placeholder="••••••••"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              icon={iconLock}
              autoComplete="new-password"
            >
              <PasswordStrength password={password} />
              {fieldErrors.password && (
                <p className="mt-1 text-[9px] font-mono text-red-500 uppercase">{fieldErrors.password}</p>
              )}
            </InputField>

            <InputField
              id="reg-confirm"
              type="password"
              label="Confirm Password"
              placeholder="••••••••"
              value={confirm}
              onChange={(e) => setConfirm(e.target.value)}
              icon={iconLock}
              autoComplete="new-password"
            >
              {fieldErrors.confirm && (
                <p className="mt-1 text-[9px] font-mono text-red-500 uppercase">{fieldErrors.confirm}</p>
              )}
            </InputField>

            <button
              type="submit"
              id="btn-register-submit"
              disabled={loading || success}
              className="btn-primary w-full py-3 mt-1"
            >
              {loading ? (
                <>
                  <svg className="w-3.5 h-3.5 animate-spin" fill="none" viewBox="0 0 24 24">
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                  </svg>
                  CREATING ACCOUNT...
                </>
              ) : (
                'CREATE ACCOUNT →'
              )}
            </button>
          </form>

          <div className="relative my-5">
            <div className="absolute inset-0 flex items-center">
              <div className="w-full border-t border-white/8" />
            </div>
            <div className="relative flex justify-center">
              <span className="px-3 text-[9px] text-white/20 font-mono uppercase tracking-widest bg-black">
                OR
              </span>
            </div>
          </div>

          <Link to="/dashboard" className="btn-ghost w-full justify-center py-2.5 text-[10px]">
            SCAN WITHOUT ACCOUNT
          </Link>
        </div>

        <p className="text-center text-white/25 text-[10px] font-mono mt-5 uppercase tracking-widest">
          HAVE AN ACCOUNT?{' '}
          <Link to="/login" className="text-white hover:text-white/70 font-bold transition-colors">
            SIGN IN →
          </Link>
        </p>
        <p className="text-center text-white/15 text-[9px] font-mono mt-2 uppercase tracking-widest">
          JWT-SECURED · BCRYPT PASSWORDS · NO PII SOLD
        </p>
      </div>
    </div>
  );
}
