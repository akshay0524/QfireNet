/**
 * components/ExplanationPanel.jsx — LLM-generated explanation display.
 *
 * Styled with sunset sky palette & Plus Jakarta Sans typography.
 */

import { useState, useEffect } from 'react';

export default function ExplanationPanel({ explanation, isLoading }) {
  const [displayedText, setDisplayedText] = useState('');
  const [isTyping, setIsTyping] = useState(false);

  useEffect(() => {
    if (!explanation) return;
    setDisplayedText('');
    setIsTyping(true);

    let i = 0;
    const speed = 12;
    const timer = setInterval(() => {
      if (i < explanation.length) {
        setDisplayedText(explanation.slice(0, i + 1));
        i++;
      } else {
        setIsTyping(false);
        clearInterval(timer);
      }
    }, speed);

    return () => clearInterval(timer);
  }, [explanation]);

  return (
    <div className="glass-card p-6 animate-fade-in border-lavender-500/20">
      <div className="flex items-center gap-3 mb-4">
        <h3 className="section-title mb-0">AI Explanation</h3>
        <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-md text-xs font-semibold bg-lavender-500/15 text-lavender-300 border border-lavender-500/30">
          <svg className="w-3 h-3 text-peach-300" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M9.813 15.904L9 18.75l-.813-2.846a4.5 4.5 0 00-3.09-3.09L2.25 12l2.846-.813a4.5 4.5 0 003.09-3.09L9 5.25l.813 2.846a4.5 4.5 0 003.09 3.09L15.75 12l-2.846.813a4.5 4.5 0 00-3.09 3.09z" />
          </svg>
          Llama 3.3 70B via Groq
        </span>
      </div>

      {isLoading ? (
        <div className="space-y-3">
          <div className="skeleton h-4 w-full rounded" />
          <div className="skeleton h-4 w-5/6 rounded" />
          <div className="skeleton h-4 w-4/6 rounded" />
          <div className="skeleton h-4 w-3/4 rounded" />
        </div>
      ) : explanation ? (
        <div className="relative">
          {/* Watermark */}
          <div className="absolute top-0 right-0 opacity-5 pointer-events-none">
            <svg className="w-20 h-20 text-peach-400" fill="currentColor" viewBox="0 0 24 24">
              <path d="M12 2a10 10 0 1 0 10 10A10 10 0 0 0 12 2zm1 17.93V18a1 1 0 0 0-2 0v1.93A8 8 0 0 1 4.07 13H6a1 1 0 0 0 0-2H4.07A8 8 0 0 1 11 4.07V6a1 1 0 0 0 2 0V4.07A8 8 0 0 1 19.93 11H18a1 1 0 0 0 0 2h1.93A8 8 0 0 1 13 19.93z" />
            </svg>
          </div>

          <p className="text-slate-200 text-sm leading-relaxed font-sans whitespace-pre-line relative z-10 font-normal">
            {displayedText}
            {isTyping && (
              <span className="inline-block w-0.5 h-4 bg-peach-400 ml-0.5 animate-pulse" />
            )}
          </p>
        </div>
      ) : (
        <p className="text-slate-500 text-sm italic font-sans">
          AI explanation will appear here after scanning.
        </p>
      )}

      {/* Disclaimer */}
      {explanation && !isLoading && (
        <p className="mt-4 pt-4 border-t border-white/5 text-slate-500 text-xs">
          ⚠ AI-generated analysis — exercise independent security verification for high-risk decisions.
        </p>
      )}
    </div>
  );
}
