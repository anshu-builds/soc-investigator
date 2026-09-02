/** @type {import('tailwindcss').Config} */
module.exports = {
  darkMode: 'class',
  content: [
    './src/pages/**/*.{js,ts,jsx,tsx,mdx}',
    './src/components/**/*.{js,ts,jsx,tsx,mdx}',
    './src/app/**/*.{js,ts,jsx,tsx,mdx}',
  ],
  theme: {
    extend: {
      fontFamily: {
        sans: ['Inter', 'system-ui', '-apple-system', 'BlinkMacSystemFont', 'sans-serif'],
        mono: ['JetBrains Mono', 'Fira Code', 'Menlo', 'monospace'],
      },
      colors: {
        // Core Console Palette
        canvas: '#0b0f14',
        panel: '#11161d',
        elevated: '#171e28',
        highlight: '#1e2838',
        ink: {
          primary: '#f3f4f6',
          secondary: '#94a3b8',
          muted: '#64748b',
          dark: '#0b0f14',
        },
        border: {
          DEFAULT: '#1f2937',
          subtle: '#182230',
          active: '#374151',
          accent: '#10b981',
          focus: '#10b981',
        },
        accent: {
          emerald: '#10b981',
          dark: '#059669',
          cyan: '#06b6d4',
          purple: '#a855f7',
          blue: '#3b82f6',
        },
        severity: {
          critical: '#ef4444',
          high: '#f97316',
          medium: '#eab308',
          low: '#38bdf8',
          info: '#64748b',
        },
        status: {
          open: '#eab308',
          investigating: '#38bdf8',
          closed: '#10b981',
          false_positive: '#64748b',
        },
      },
      animation: {
        'pulse-slow': 'pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'pulse-subtle': 'pulseSubtle 2.5s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'fade-in': 'fadeIn 0.15s ease-out',
        'fade-out': 'fadeOut 0.12s ease-in',
        'slide-in': 'slideIn 0.15s cubic-bezier(0.16, 1, 0.3, 1)',
        'slide-in-right': 'slideInRight 0.22s cubic-bezier(0.16, 1, 0.3, 1)',
        'scale-in': 'scaleIn 0.15s cubic-bezier(0.16, 1, 0.3, 1)',
      },
      keyframes: {
        fadeIn: {
          from: { opacity: '0' },
          to: { opacity: '1' },
        },
        fadeOut: {
          from: { opacity: '1' },
          to: { opacity: '0' },
        },
        slideIn: {
          from: { opacity: '0', transform: 'translateY(4px)' },
          to: { opacity: '1', transform: 'translateY(0)' },
        },
        slideInRight: {
          from: { opacity: '0', transform: 'translateX(100%)' },
          to: { opacity: '1', transform: 'translateX(0)' },
        },
        scaleIn: {
          from: { opacity: '0', transform: 'scale(0.97)' },
          to: { opacity: '1', transform: 'scale(1)' },
        },
        pulseSubtle: {
          '0%, 100%': { opacity: '1' },
          '50%': { opacity: '0.65' },
        },
      },
      boxShadow: {
        subtle: '0 1px 2px 0 rgba(0, 0, 0, 0.4)',
        panel: '0 4px 12px 0 rgba(0, 0, 0, 0.5)',
        glow: '0 0 15px -3px rgba(16, 185, 129, 0.15)',
      },
    },
  },
  plugins: [],
}
