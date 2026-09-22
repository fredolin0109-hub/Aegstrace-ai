/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        soc: {
          dark: '#050811',
          card: '#0c1322',
          cardHover: '#111b30',
          border: '#1e293b',
          borderLight: '#334155',
          cyan: '#06b6d4',
          accent: '#3b82f6',
          safe: '#10b981',
          warning: '#f59e0b',
          danger: '#f43f5e',
          critical: '#e11d48',
          purple: '#8b5cf6',
        }
      },
      fontFamily: {
        mono: ['"JetBrains Mono"', 'Menlo', 'Monaco', 'Consolas', '"Liberation Mono"', '"Courier New"', 'monospace'],
      },
      animation: {
        'pulse-slow': 'pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'glow': 'glow 2s ease-in-out infinite alternate',
      },
      keyframes: {
        glow: {
          '0%': { boxShadow: '0 0 5px rgba(6, 182, 212, 0.2)' },
          '100%': { boxShadow: '0 0 15px rgba(6, 182, 212, 0.6)' },
        }
      }
    },
  },
  plugins: [],
}
