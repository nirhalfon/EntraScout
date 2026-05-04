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
        scout: {
          bg: '#0a0e14',
          panel: '#0f1521',
          'panel-2': '#131b29',
          'log-bg': '#08090d',
          border: '#1c2433',
          'border-2': '#243049',
          text: '#c9d1d9',
          muted: '#6b7280',
          'muted-2': '#4a5568',
          accent: 'var(--color-accent)',
          'accent-dim': 'var(--color-accent-dim)',
          critical: 'var(--color-critical)',
          high: 'var(--color-high)',
          medium: 'var(--color-medium)',
          low: 'var(--color-low)',
          info: 'var(--color-info)',
        }
      },
      fontFamily: {
        mono: ['"JetBrains Mono"', 'ui-monospace', '"SFMono-Regular"', 'Menlo', 'Consolas', 'monospace'],
        sans: ['Inter', 'system-ui', '-apple-system', 'sans-serif'],
      },
      fontSize: {
        '2xs': ['0.625rem', { lineHeight: '1.4' }],
      },
      animation: {
        'cell-pulse': 'cell-pulse 0.8s ease-in-out infinite',
        'dot-pulse': 'dot-pulse 1.2s ease-in-out infinite',
      },
      keyframes: {
        'cell-pulse': {
          '0%, 100%': { boxShadow: '0 0 0 oklch(0.50 0.12 220 / 0.6)' },
          '50%': { boxShadow: '0 0 8px oklch(0.50 0.12 220 / 0.6)' },
        },
        'dot-pulse': {
          '0%, 100%': { opacity: '1', transform: 'scale(1)' },
          '50%': { opacity: '0.4', transform: 'scale(1.3)' },
        },
      },
      plugins: [
        function({ addUtilities }) {
          addUtilities({
            '.hairline': { border: '1px solid #1c2433' },
            '.hairline-2': { border: '1px solid #243049' },
            '.scrollbar-console': {
              'scrollbar-width': 'thin',
              'scrollbar-color': '#243049 transparent',
            },
            '.scrollbar-console::-webkit-scrollbar': { width: '6px' },
            '.scrollbar-console::-webkit-scrollbar-track': { background: 'transparent' },
            '.scrollbar-console::-webkit-scrollbar-thumb': { background: '#243049', borderRadius: '2px' },
          })
        }
      ],
    },
  },
}