/**
 * components/ScanForm.jsx — Nothing OS Tabbed Scan Input Form.
 *
 * All logic preserved exactly from original. Only visual redesign:
 *   - Flat segmented tab switcher (active = white fill / black text)
 *   - Uppercase tracked labels, hairline borders, no gradients
 *   - "ANALYZE →" primary button
 *   - Drop zones: dashed 1px border, no gradient fills
 */

import { useState, useRef, useCallback } from 'react';
import { scanAPI } from '../api/client';

const TABS = [
  { id: 'website', label: 'URL',   sym: '◈' },
  { id: 'email',   label: 'EMAIL', sym: '◆' },
  { id: 'apk',     label: 'APK',   sym: '◉' },
];

const EMAIL_MODE_PASTE      = 'paste';
const EMAIL_MODE_SCREENSHOT = 'screenshot';
const MAX_IMAGE_BYTES       = 5 * 1024 * 1024;

export default function ScanForm({ onResult, onStart, onError }) {
  const [activeTab, setActiveTab] = useState('website');
  const [loading, setLoading]     = useState(false);
  const [error, setError]         = useState('');

  // Website
  const [url, setUrl] = useState('');

  // Email
  const [emailMode, setEmailMode]       = useState(EMAIL_MODE_PASTE);
  const [senderEmail, setSenderEmail]   = useState('');
  const [emailSubject, setEmailSubject] = useState('');
  const [emailBody, setEmailBody]       = useState('');

  // Screenshot
  const [screenshotFile, setScreenshotFile]       = useState(null);
  const [screenshotPreview, setScreenshotPreview] = useState(null);
  const [isDragOver, setIsDragOver]               = useState(false);
  const screenshotInputRef = useRef(null);

  // APK
  const [apkFile, setApkFile]   = useState(null);
  const apkFileInputRef         = useRef(null);

  // Sender email validation
  const [senderEmailError, setSenderEmailError] = useState('');
  const EMAIL_RE = /^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$/;

  const validateSenderEmail = (val) => {
    if (!val.trim()) { setSenderEmailError(''); return true; }
    if (!EMAIL_RE.test(val.trim())) {
      setSenderEmailError('INVALID EMAIL ADDRESS');
      return false;
    }
    setSenderEmailError('');
    return true;
  };

  const isEmailPasteReady = (
    emailMode === EMAIL_MODE_PASTE
    && senderEmail.trim()
    && emailSubject.trim()
    && emailBody.trim()
    && !senderEmailError
  );
  const isEmailScreenshotReady = emailMode === EMAIL_MODE_SCREENSHOT && !!screenshotFile;
  const isSubmitDisabled = loading || (() => {
    if (activeTab === 'website') return !url.trim();
    if (activeTab === 'email')   return !isEmailPasteReady && !isEmailScreenshotReady;
    if (activeTab === 'apk')     return !apkFile;
    return true;
  })();

  const handleScreenshotFile = useCallback((file) => {
    if (!file) return;
    const allowed = ['image/png', 'image/jpeg', 'image/jpg'];
    if (!allowed.includes(file.type.toLowerCase())) {
      setError('ONLY PNG, JPG, OR JPEG IMAGES ARE ACCEPTED.');
      return;
    }
    if (file.size > MAX_IMAGE_BYTES) {
      setError(`IMAGE TOO LARGE (${(file.size / 1024 / 1024).toFixed(1)} MB). MAX IS 5 MB.`);
      return;
    }
    setError('');
    setScreenshotFile(file);
    const reader = new FileReader();
    reader.onload = (e) => setScreenshotPreview(e.target.result);
    reader.readAsDataURL(file);
  }, []);

  const handleScreenshotDrop = useCallback((e) => {
    e.preventDefault();
    setIsDragOver(false);
    handleScreenshotFile(e.dataTransfer.files[0]);
  }, [handleScreenshotFile]);

  const handleAPKDrop = (e) => {
    e.preventDefault();
    const dropped = e.dataTransfer.files[0];
    if (dropped?.name.endsWith('.apk')) setApkFile(dropped);
    else setError('ONLY .APK FILES ARE ACCEPTED.');
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);
    onStart?.(activeTab);

    try {
      let response;

      if (activeTab === 'website') {
        if (!url.trim()) throw new Error('PLEASE ENTER A VALID URL.');
        response = await scanAPI.scanWebsite(url.trim());

      } else if (activeTab === 'email') {
        if (emailMode === EMAIL_MODE_PASTE) {
          if (!senderEmail.trim() || !emailSubject.trim() || !emailBody.trim())
            throw new Error('PLEASE FILL IN ALL THREE FIELDS.');
          if (!validateSenderEmail(senderEmail))
            throw new Error('PLEASE ENTER A VALID SENDER EMAIL ADDRESS.');
          response = await scanAPI.scanEmail({
            senderEmail: senderEmail.trim(),
            subject:     emailSubject.trim(),
            body:        emailBody.trim(),
          });
        } else {
          if (!screenshotFile) throw new Error('PLEASE UPLOAD AN EMAIL SCREENSHOT.');
          response = await scanAPI.scanEmailScreenshot(screenshotFile);
        }

      } else if (activeTab === 'apk') {
        if (!apkFile) throw new Error('PLEASE SELECT AN APK FILE.');
        response = await scanAPI.scanAPK(apkFile);
      }

      onResult({ data: response.data, scanType: activeTab });
    } catch (err) {
      const msg = err.response?.data?.detail || err.message || 'SCAN FAILED. PLEASE TRY AGAIN.';
      setError(typeof msg === 'string' ? msg.toUpperCase() : JSON.stringify(msg).toUpperCase());
      onError?.();
    } finally {
      setLoading(false);
    }
  };

  const switchEmailMode = (mode) => {
    setEmailMode(mode);
    setError('');
  };

  return (
    <div className="card overflow-hidden">
      {/* ── Tab Selector ─────────────────────────────────────────────────── */}
      <div className="flex border-b" style={{ borderColor: 'var(--border)', background: 'var(--bg-raised)' }}>
        {TABS.map((tab) => (
          <button
            key={tab.id}
            onClick={() => { setActiveTab(tab.id); setError(''); }}
            id={`tab-${tab.id}`}
            className={`flex-1 flex items-center justify-center gap-2 px-4 py-3 text-xs font-semibold uppercase tracking-wider transition-all duration-150 ${
              activeTab === tab.id
                ? 'text-[var(--accent)] bg-[var(--bg-card)] border-b-2 border-[var(--accent)]'
                : 'text-[var(--text-secondary)] hover:text-[var(--text-primary)] hover:bg-white/[0.02]'
            }`}
          >
            <span className={activeTab === tab.id ? 'text-[var(--accent)]' : 'opacity-40'}>{tab.sym}</span>
            {tab.label}
          </button>
        ))}
      </div>

      <form onSubmit={handleSubmit} className="p-5 space-y-4">

        {/* ── Website tab ───────────────────────────────────────────────── */}
        {activeTab === 'website' && (
          <div className="animate-fade-in">
            <label className="block text-xs font-semibold mb-2 uppercase tracking-wider text-[var(--text-secondary)]">
              WEBSITE URL
            </label>
            <input
              id="input-website-url"
              type="url"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="https://example.com"
              className="input-field"
              required
            />
            <p className="mt-2 text-[11px] font-mono text-[var(--text-muted)] tracking-wide">
              SSL CERT · WHOIS AGE · PHISHING · ENTROPY · PQC READINESS
            </p>
          </div>
        )}

        {/* ── Email tab ─────────────────────────────────────────────────── */}
        {activeTab === 'email' && (
          <div className="animate-fade-in space-y-4">

            {/* Mode toggle */}
            <div className="flex border rounded-md overflow-hidden" style={{ borderColor: 'var(--border)', background: 'var(--bg-raised)' }}>
              <button
                type="button"
                id="email-mode-paste"
                onClick={() => switchEmailMode(EMAIL_MODE_PASTE)}
                className={`flex-1 flex items-center justify-center gap-1.5 px-3 py-2 text-xs font-semibold uppercase tracking-wider transition-all duration-150 ${
                  emailMode === EMAIL_MODE_PASTE
                    ? 'bg-[var(--accent-dim)] text-[var(--accent)] border-r border-[var(--accent-border)]'
                    : 'text-[var(--text-secondary)] hover:text-[var(--text-primary)] hover:bg-white/[0.02]'
                }`}
              >
                <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2" />
                </svg>
                PASTE TEXT
              </button>
              <button
                type="button"
                id="email-mode-screenshot"
                onClick={() => switchEmailMode(EMAIL_MODE_SCREENSHOT)}
                className={`flex-1 flex items-center justify-center gap-1.5 px-3 py-2 text-xs font-semibold uppercase tracking-wider transition-all duration-150 ${
                  emailMode === EMAIL_MODE_SCREENSHOT
                    ? 'bg-[var(--accent-dim)] text-[var(--accent)] border-l border-[var(--accent-border)]'
                    : 'text-[var(--text-secondary)] hover:text-[var(--text-primary)] hover:bg-white/[0.02]'
                }`}
              >
                <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M2.25 15.75l5.159-5.159a2.25 2.25 0 013.182 0l5.159 5.159m-1.5-1.5l1.409-1.409a2.25 2.25 0 013.182 0l2.909 2.909m-18 3.75h16.5a1.5 1.5 0 001.5-1.5V6a1.5 1.5 0 00-1.5-1.5H3.75A1.5 1.5 0 002.25 6v12a1.5 1.5 0 001.5 1.5zm10.5-11.25h.008v.008h-.008V8.25zm.375 0a.375.375 0 11-.75 0 .375.375 0 01.75 0z" />
                </svg>
                SCREENSHOT
              </button>
            </div>

            {/* PASTE MODE */}
            {emailMode === EMAIL_MODE_PASTE && (
              <div className="space-y-3 animate-fade-in">
                {/* Sender Email */}
                <div>
                  <label className="block text-xs font-semibold mb-1.5 uppercase tracking-wider text-[var(--text-secondary)]">
                    SENDER EMAIL <span className="opacity-60 normal-case tracking-normal font-normal">(From: field)</span>
                  </label>
                  <input
                    id="input-email-sender"
                    type="email"
                    value={senderEmail}
                    onChange={(e) => { setSenderEmail(e.target.value); validateSenderEmail(e.target.value); }}
                    onBlur={(e) => validateSenderEmail(e.target.value)}
                    placeholder="sender@example.com"
                    className={`input-field ${senderEmailError ? 'border-red-500/60' : ''}`}
                    autoComplete="off"
                    spellCheck={false}
                  />
                  {senderEmailError && (
                    <p className="mt-1 text-[10px] font-mono text-red-400 uppercase">{senderEmailError}</p>
                  )}
                </div>

                {/* Subject */}
                <div>
                  <label className="block text-xs font-semibold mb-1.5 uppercase tracking-wider text-[var(--text-secondary)]">
                    SUBJECT LINE
                  </label>
                  <input
                    id="input-email-subject"
                    type="text"
                    value={emailSubject}
                    onChange={(e) => setEmailSubject(e.target.value)}
                    placeholder="Your account has been suspended"
                    className="input-field"
                  />
                </div>

                {/* Body */}
                <div>
                  <label className="block text-xs font-semibold mb-1.5 uppercase tracking-wider text-[var(--text-secondary)]">
                    EMAIL BODY
                  </label>
                  <textarea
                    id="input-email-body"
                    value={emailBody}
                    onChange={(e) => setEmailBody(e.target.value)}
                    placeholder="Paste the email body text here..."
                    rows={6}
                    className="input-field resize-y leading-relaxed text-xs"
                  />
                </div>
                <p className="text-[11px] font-mono text-[var(--text-muted)] tracking-wide">
                  ALL THREE FIELDS REQUIRED · SENDER DOMAIN CROSS-CHECKED BEFORE LLM ANALYSIS
                </p>
              </div>
            )}

            {/* SCREENSHOT MODE */}
            {emailMode === EMAIL_MODE_SCREENSHOT && (
              <div className="space-y-3 animate-fade-in">
                {screenshotFile ? (
                  <div className="card overflow-hidden">
                    {screenshotPreview && (
                      <img
                        src={screenshotPreview}
                        alt="Email screenshot preview"
                        className="w-full max-h-48 object-contain bg-black/40"
                        id="email-screenshot-preview"
                      />
                    )}
                    <div className="flex items-center justify-between px-3.5 py-2.5 border-t border-[var(--border)]">
                      <div>
                        <p className="text-[var(--text-primary)] text-xs font-mono truncate max-w-[240px]">
                          {screenshotFile.name}
                        </p>
                        <p className="text-[var(--text-muted)] text-[10px] font-mono">
                          {(screenshotFile.size / 1024 / 1024).toFixed(2)} MB
                        </p>
                      </div>
                      <button
                        type="button"
                        id="btn-remove-screenshot"
                        onClick={() => { setScreenshotFile(null); setScreenshotPreview(null); setError(''); }}
                        className="text-red-400 hover:text-red-300 text-xs font-semibold uppercase tracking-wider transition-colors"
                      >
                        REMOVE
                      </button>
                    </div>
                  </div>
                ) : (
                  <div
                    id="screenshot-dropzone"
                    onDrop={handleScreenshotDrop}
                    onDragOver={(e) => { e.preventDefault(); setIsDragOver(true); }}
                    onDragLeave={() => setIsDragOver(false)}
                    onClick={() => screenshotInputRef.current?.click()}
                    className={`border border-dashed p-8 text-center cursor-pointer transition-all duration-150 rounded-lg ${
                      isDragOver
                        ? 'border-[var(--accent)] bg-[var(--accent-dim)]/20'
                        : 'border-[var(--border-strong)] bg-[var(--bg-raised)]/40 hover:border-[var(--accent)] hover:bg-[var(--accent-dim)]/10'
                    }`}
                  >
                    <div className="flex flex-col items-center gap-3">
                      <div className={`w-10 h-10 rounded-lg border flex items-center justify-center transition-all duration-150 ${
                        isDragOver ? 'border-[var(--accent)] text-[var(--accent)]' : 'border-[var(--border)] text-[var(--text-secondary)]'
                      }`}>
                        <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                          <path strokeLinecap="round" strokeLinejoin="round" d="M3 16.5v2.25A2.25 2.25 0 005.25 21h13.5A2.25 2.25 0 0021 18.75V16.5m-13.5-9L12 3m0 0l4.5 4.5M12 3v13.5" />
                        </svg>
                      </div>
                      <div>
                        <p className="text-[var(--text-primary)] text-xs font-semibold uppercase tracking-wider">
                          {isDragOver ? 'DROP HERE' : 'DROP SCREENSHOT OR CLICK TO BROWSE'}
                        </p>
                        <p className="text-[var(--text-muted)] text-[10px] font-mono mt-1 uppercase tracking-wide">
                          PNG · JPG · JPEG · MAX 5 MB · OCR AUTO-EXTRACTS TEXT
                        </p>
                      </div>
                    </div>
                    <input
                      ref={screenshotInputRef}
                      type="file"
                      accept=".png,.jpg,.jpeg,image/png,image/jpeg"
                      onChange={(e) => handleScreenshotFile(e.target.files?.[0])}
                      className="hidden"
                      id="screenshot-file-input"
                    />
                  </div>
                )}

                {/* OCR notice */}
                <div className="flex items-start gap-2 px-3 py-2 border rounded-md" style={{ borderColor: 'var(--border)', background: 'var(--bg-raised)' }}>
                  <span className="text-[var(--accent)] text-xs font-mono mt-0.5 flex-shrink-0">ℹ</span>
                  <p className="text-[var(--text-secondary)] text-[11px] font-mono tracking-wide">
                    OCR + AI analysis takes 15–30 seconds. Use paste mode for instant results.
                  </p>
                </div>
              </div>
            )}
          </div>
        )}

        {/* ── APK tab ───────────────────────────────────────────────────── */}
        {activeTab === 'apk' && (
          <div className="animate-fade-in">
            <label className="block text-xs font-semibold mb-2 uppercase tracking-wider text-[var(--text-secondary)]">
              ANDROID APK PACKAGE
            </label>
            <div
              id="apk-dropzone"
              onDrop={handleAPKDrop}
              onDragOver={(e) => e.preventDefault()}
              onClick={() => apkFileInputRef.current?.click()}
              className={`border border-dashed p-8 text-center cursor-pointer transition-all duration-150 rounded-lg ${
                apkFile
                  ? 'border-[var(--accent)] bg-[var(--accent-dim)]/15'
                  : 'border-[var(--border-strong)] bg-[var(--bg-raised)]/40 hover:border-[var(--accent)] hover:bg-[var(--accent-dim)]/10'
              }`}
            >
              {apkFile ? (
                <div className="flex flex-col items-center gap-2">
                  <div className="w-10 h-10 rounded-lg border border-[var(--accent-border)] bg-[var(--accent-dim)] flex items-center justify-center text-[var(--accent)]">
                    <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                      <path strokeLinecap="round" strokeLinejoin="round" d="M9 12.75L11.25 15 15 9.75M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                    </svg>
                  </div>
                  <p className="text-[var(--text-primary)] text-xs font-mono font-semibold">{apkFile.name}</p>
                  <p className="text-[var(--text-muted)] text-[10px] font-mono uppercase">
                    {(apkFile.size / 1024 / 1024).toFixed(2)} MB
                  </p>
                  <button
                    type="button"
                    onClick={(e) => { e.stopPropagation(); setApkFile(null); }}
                    className="text-red-400 hover:text-red-300 text-xs font-semibold uppercase tracking-wider transition-colors mt-1"
                  >
                    REMOVE
                  </button>
                </div>
              ) : (
                <div className="flex flex-col items-center gap-3">
                  <div className="w-10 h-10 rounded-lg border border-[var(--border)] flex items-center justify-center text-[var(--text-secondary)]">
                    <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                      <path strokeLinecap="round" strokeLinejoin="round" d="M3 16.5v2.25A2.25 2.25 0 005.25 21h13.5A2.25 2.25 0 0021 18.75V16.5m-13.5-9L12 3m0 0l4.5 4.5M12 3v13.5" />
                    </svg>
                  </div>
                  <div>
                    <p className="text-[var(--text-primary)] text-xs font-semibold uppercase tracking-wider">
                      DROP APK OR CLICK TO BROWSE
                    </p>
                    <p className="text-[var(--text-muted)] text-[10px] font-mono mt-1 uppercase tracking-wide">
                      .APK ONLY · STATIC ANALYSIS · DELETED IMMEDIATELY AFTER SCAN
                    </p>
                  </div>
                </div>
              )}
              <input
                ref={apkFileInputRef}
                type="file"
                accept=".apk"
                onChange={(e) => setApkFile(e.target.files[0] || null)}
                className="hidden"
                id="apk-file-input"
              />
            </div>
          </div>
        )}

        {/* ── Error ─────────────────────────────────────────────────────── */}
        {error && (
          <div className="flex items-start gap-2.5 p-3 border border-red-500/30 bg-red-500/5 animate-fade-in"
            style={{ borderRadius: '2px' }}>
            <span className="text-red-500 text-[10px] font-mono mt-0.5 flex-shrink-0">✕</span>
            <p className="text-red-400 text-xs font-mono">{error}</p>
          </div>
        )}

        {/* ── Analyze button ────────────────────────────────────────────── */}
        <button
          type="submit"
          id="btn-scan-submit"
          disabled={isSubmitDisabled}
          className="btn-primary w-full py-3 mt-1 disabled:opacity-25 disabled:cursor-not-allowed"
        >
          {loading ? (
            <>
              <svg className="w-3.5 h-3.5 animate-spin" fill="none" viewBox="0 0 24 24">
                <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
              </svg>
              {activeTab === 'email' && emailMode === EMAIL_MODE_SCREENSHOT
                ? 'RUNNING OCR + AI...'
                : 'ANALYZING SIGNALS...'}
            </>
          ) : (
            'ANALYZE →'
          )}
        </button>
      </form>
    </div>
  );
}
