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
        ink: {
          primary: '#f3f4f6',
          secondary: '#9ca3af',
          muted: '#6b7280',
          dark: '#111827',
        },
        border: {
          DEFAULT: '#1f2937',
          subtle: '#182230',
          active: '#374151',
          accent: '#10b981',
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
          low: '#64748b',
          info: '#3b82f6',
        },
        status: {
          open: '#eab308',
          investigating: '#3b82f6',
          closed: '#10b981',
          false_positive: '#64748b',
        },
      },
      animation: {
        'pulse-slow': 'pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'fade-in': 'fadeIn 0.2s ease-out',
        'slide-in': 'slideIn 0.2s ease-out',
      },
      keyframes: {
        fadeIn: {
          from: { opacity: '0' },
          to: { opacity: '1' },
        },
        slideIn: {
          from: { opacity: '0', transform: 'translateY(4px)' },
          to: { opacity: '1', transform: 'translateY(0)' },
        },
      },
      boxShadow: {
        subtle: '0 1px 2px 0 rgba(0, 0, 0, 0.4)',
        panel: '0 4px 12px 0 rgba(0, 0, 0, 0.5)',
      },
    },
  },
  plugins: [],
}
