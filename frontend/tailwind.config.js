/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    './src/pages/**/*.{js,ts,jsx,tsx,mdx}',
    './src/components/**/*.{js,ts,jsx,tsx,mdx}',
    './src/app/**/*.{js,ts,jsx,tsx,mdx}',
  ],
  theme: {
    extend: {
      fontFamily: {
        sans: ['Inter', 'system-ui', 'sans-serif'],
        mono: ['JetBrains Mono', 'Fira Code', 'monospace'],
      },
      colors: {
        // SOC Dark Theme Palette
        bg: {
          primary:   '#0a0e1a',
          secondary: '#0f1629',
          tertiary:  '#141c35',
          card:      '#111827',
          hover:     '#1a2545',
        },
        border: {
          DEFAULT: '#1e2d4d',
          bright:  '#2d4a7a',
          glow:    '#3b5998',
        },
        accent: {
          cyan:   '#00d4ff',
          blue:   '#3b82f6',
          purple: '#8b5cf6',
          green:  '#10b981',
        },
        severity: {
          critical: '#ef4444',
          high:     '#f97316',
          medium:   '#eab308',
          low:      '#22c55e',
          info:     '#3b82f6',
        },
        phase: {
          initial:   '#6366f1',
          compromise:'#ef4444',
          escalation:'#f97316',
          impact:    '#dc2626',
        },
      },
      backgroundImage: {
        'grid-pattern': "linear-gradient(rgba(59,91,152,0.05) 1px, transparent 1px), linear-gradient(90deg, rgba(59,91,152,0.05) 1px, transparent 1px)",
        'glow-cyan': 'radial-gradient(ellipse at top, rgba(0,212,255,0.15) 0%, transparent 60%)',
        'glow-blue': 'radial-gradient(ellipse at center, rgba(59,130,246,0.1) 0%, transparent 60%)',
      },
      animation: {
        'pulse-slow':   'pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'glow':         'glow 2s ease-in-out infinite alternate',
        'slide-in':     'slideIn 0.3s ease-out',
        'fade-in':      'fadeIn 0.4s ease-out',
        'scan-line':    'scanLine 4s linear infinite',
      },
      keyframes: {
        glow: {
          from: { boxShadow: '0 0 5px rgba(0,212,255,0.3)' },
          to:   { boxShadow: '0 0 20px rgba(0,212,255,0.6), 0 0 40px rgba(0,212,255,0.2)' },
        },
        slideIn: {
          from: { opacity: '0', transform: 'translateY(10px)' },
          to:   { opacity: '1', transform: 'translateY(0)' },
        },
        fadeIn: {
          from: { opacity: '0' },
          to:   { opacity: '1' },
        },
        scanLine: {
          '0%':   { transform: 'translateY(-100%)' },
          '100%': { transform: 'translateY(400%)' },
        },
      },
      boxShadow: {
        'card':     '0 4px 24px rgba(0,0,0,0.4)',
        'glow-sm':  '0 0 8px rgba(0,212,255,0.3)',
        'glow-md':  '0 0 16px rgba(0,212,255,0.4)',
        'glow-lg':  '0 0 32px rgba(0,212,255,0.3), 0 0 64px rgba(0,212,255,0.1)',
        'critical': '0 0 16px rgba(239,68,68,0.4)',
        'high':     '0 0 16px rgba(249,115,22,0.4)',
      },
    },
  },
  plugins: [],
}
