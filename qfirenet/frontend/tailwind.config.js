/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        // ── Base surface palette (GitHub dark / deep-space) ──────────────
        surface: {
          base:    '#0A0E14',   // page background
          raised:  '#0D1117',   // slightly above base
          card:    '#151B23',   // cards / panels
          overlay: '#1C2333',   // dropdowns / tooltips
          border:  '#21262D',   // card borders
          muted:   '#30363D',   // subtle borders
        },

        // ── Text hierarchy ───────────────────────────────────────────────
        text: {
          primary:   '#E6EDF3',  // headings, main content
          secondary: '#8B949E',  // labels, subtitles
          muted:     '#484F58',  // placeholders, disabled
        },

        // ── Accent: Cyan / Teal (primary interactive color) ─────────────
        cyan: {
          400: '#2DD4BF',
          500: '#14B8A6',
          glow: '#00D9FF',
        },

        // ── Risk colors ──────────────────────────────────────────────────
        risk: {
          high:   '#FF3B5C',   // red — high risk / critical
          medium: '#FFB020',   // amber — medium risk
          low:    '#3DDC84',   // green — safe / low risk
        },

        // ── Semantic aliases ─────────────────────────────────────────────
        accent:  '#00D9FF',
        danger:  '#FF3B5C',
        warning: '#FFB020',
        success: '#3DDC84',
      },

      fontFamily: {
        sans:    ['"Inter"', 'system-ui', 'sans-serif'],
        heading: ['"Space Grotesk"', '"Inter"', 'system-ui', 'sans-serif'],
        mono:    ['"JetBrains Mono"', '"Fira Code"', 'Courier New', 'monospace'],
      },

      fontSize: {
        // Hero sizes
        'hero':    ['clamp(2.5rem,6vw,4.5rem)', { lineHeight: '1.05', letterSpacing: '-0.03em' }],
        'display': ['clamp(1.75rem,4vw,2.5rem)', { lineHeight: '1.1', letterSpacing: '-0.02em' }],
      },

      borderRadius: {
        DEFAULT: '6px',
        sm:  '4px',
        md:  '6px',
        lg:  '8px',
        xl:  '12px',
        '2xl': '16px',
        full: '9999px',
      },

      animation: {
        'fade-in':        'fadeIn 0.2s ease-out',
        'fade-in-up':     'fadeInUp 0.25s ease-out',
        'slide-up':       'slideUp 0.2s ease-out',
        'scale-in':       'scaleIn 0.15s ease-out',
        'pulse-slow':     'pulse 2.5s ease-in-out infinite',
        'spin-slow':      'spin 3s linear infinite',
        'ping-slow':      'ping 2s cubic-bezier(0,0,0.2,1) infinite',
        'glow-pulse':     'glowPulse 2s ease-in-out infinite',
        'slide-in-right': 'slideInRight 0.3s ease-out',
        'float-up':       'floatUp 0.4s ease-out forwards',
      },

      keyframes: {
        fadeIn:  { '0%': { opacity: '0' }, '100%': { opacity: '1' } },
        fadeInUp: {
          '0%':   { opacity: '0', transform: 'translateY(10px)' },
          '100%': { opacity: '1', transform: 'translateY(0)' },
        },
        slideUp: {
          '0%':   { opacity: '0', transform: 'translateY(8px)' },
          '100%': { opacity: '1', transform: 'translateY(0)' },
        },
        scaleIn: {
          '0%':   { opacity: '0', transform: 'scale(0.95)' },
          '100%': { opacity: '1', transform: 'scale(1)' },
        },
        glowPulse: {
          '0%, 100%': { boxShadow: '0 0 8px rgba(0,217,255,0.3)' },
          '50%':      { boxShadow: '0 0 24px rgba(0,217,255,0.7)' },
        },
        slideInRight: {
          '0%':   { opacity: '0', transform: 'translateX(12px)' },
          '100%': { opacity: '1', transform: 'translateX(0)' },
        },
        floatUp: {
          '0%':   { opacity: '0', transform: 'translateY(16px)' },
          '100%': { opacity: '1', transform: 'translateY(0)' },
        },
        // Legacy
        gaugeFill: {
          '0%':   { strokeDashoffset: '339.3' },
          '100%': { strokeDashoffset: 'var(--gauge-offset)' },
        },
      },

      boxShadow: {
        'card':       '0 1px 3px rgba(0,0,0,0.4), 0 0 0 1px rgba(255,255,255,0.05)',
        'card-hover': '0 4px 12px rgba(0,0,0,0.5), 0 0 0 1px rgba(255,255,255,0.1)',
        'glow-cyan':  '0 0 20px rgba(0,217,255,0.35)',
        'glow-red':   '0 0 20px rgba(255,59,92,0.35)',
        'glow-green': '0 0 20px rgba(61,220,132,0.25)',
        'inset-top':  'inset 0 1px 0 rgba(255,255,255,0.06)',
      },

      backgroundImage: {
        'grid-subtle':   "linear-gradient(rgba(255,255,255,0.025) 1px, transparent 1px), linear-gradient(90deg, rgba(255,255,255,0.025) 1px, transparent 1px)",
        'dot-subtle':    "radial-gradient(circle, rgba(255,255,255,0.07) 1px, transparent 1px)",
        'hero-gradient': "radial-gradient(ellipse 80% 60% at 50% -10%, rgba(0,217,255,0.08) 0%, transparent 60%)",
        'panel-shine':   "linear-gradient(135deg, rgba(255,255,255,0.04) 0%, transparent 50%)",
      },

      transitionDuration: { DEFAULT: '150ms' },
      transitionTimingFunction: { DEFAULT: 'ease-out' },
    },
  },
  plugins: [],
}
