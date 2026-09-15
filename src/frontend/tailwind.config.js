/** @type {import('tailwindcss').Config} */
export default {
  content: [
    './index.html',
    './src/**/*.{js,jsx}',
  ],
  theme: {
    extend: {
      colors: {
        // Graphite / charcoal palette
        console: {
          950: '#0a0c0f',
          900: '#0e1117',
          850: '#12161d',
          800: '#161b24',
          750: '#1b2130',
          700: '#1f273a',
          600: '#263045',
          500: '#2e3a52',
          400: '#3d4f6b',
          300: '#546a8a',
        },
        // Intelligence accent — cyan/blue
        intel: {
          500: '#38bdf8',
          400: '#7dd3fc',
          300: '#bae6fd',
          600: '#0ea5e9',
        },
        // Threat priority colours
        threat: {
          critical: '#ef4444',
          high:     '#f97316',
          medium:   '#eab308',
          low:      '#6b7280',
        },
        border: {
          DEFAULT: '#1e2a3b',
          subtle: '#1a2334',
          glow: '#1e3a5f',
        },
      },
      fontFamily: {
        mono: ['JetBrains Mono', 'Fira Code', 'Consolas', 'monospace'],
      },
      animation: {
        'pulse-subtle': 'pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
      },
    },
  },
  plugins: [],
};
