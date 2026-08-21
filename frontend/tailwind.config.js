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
        ink: '#18221F',
        jade: '#7FBF9A',
        sage: '#B7D98E',
        sky: '#CFE9F0',
        cream: '#EEF6E3',
        bg: {
          primary:   '#F5FBF7',
          secondary: '#EEF6E3',
          tertiary:  '#CFE9F0',
          card:      '#FFFFFF',
          hover:     '#E5F2E8',
        },
        border: {
          DEFAULT: 'rgba(24, 34, 31, 0.14)',
          bright:  'rgba(77, 154, 121, 0.55)',
          glow:    '#7FBF9A',
        },
        accent: {
          cyan:   '#7FBF9A',
          blue:   '#4D9A79',
          purple: '#708B84',
          green:  '#5C9B71',
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
