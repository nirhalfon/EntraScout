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
          bg: '#0a0e1a',
          panel: '#111827',
          elevated: '#1a2236',
          border: '#1e3a5f',
          muted: '#6b8cae',
          text: '#e6edf3',
          accent: '#0078D4',
          'accent-glow': '#2899f5',
          critical: '#ff3b3b',
          high: '#ff8c42',
          medium: '#ffc107',
          low: '#00c853',
          info: '#00b0ff',
        }
      },
      animation: {
        'pulse-ring': 'pulse-ring 2s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'glow-pulse': 'glow-pulse 2s ease-in-out infinite',
        'dash-flow': 'dash-flow 1.5s linear infinite',
        'typing': 'typing 3.5s steps(40, end)',
        'blink': 'blink 1s step-end infinite',
        'float': 'float 6s ease-in-out infinite',
        'radar': 'radar 3s ease-out infinite',
        'grid-drift': 'grid-drift 20s linear infinite',
      },
      keyframes: {
        'pulse-ring': {
          '0%': { transform: 'scale(0.8)', opacity: '1' },
          '100%': { transform: 'scale(2.4)', opacity: '0' },
        },
        'glow-pulse': {
          '0%, 100%': { boxShadow: '0 0 5px rgba(0,120,212,0.3)' },
          '50%': { boxShadow: '0 0 20px rgba(0,120,212,0.6), 0 0 40px rgba(0,120,212,0.2)' },
        },
        'dash-flow': {
          '0%': { strokeDashoffset: '24' },
          '100%': { strokeDashoffset: '0' },
        },
        'typing': {
          'from': { width: '0' },
          'to': { width: '100%' },
        },
        'blink': {
          '0%, 100%': { opacity: '1' },
          '50%': { opacity: '0' },
        },
        'float': {
          '0%, 100%': { transform: 'translateY(0px)' },
          '50%': { transform: 'translateY(-10px)' },
        },
        'radar': {
          '0%': { transform: 'scale(0)', opacity: '0.6' },
          '100%': { transform: 'scale(2.5)', opacity: '0' },
        },
        'grid-drift': {
          '0%': { backgroundPosition: '0 0' },
          '100%': { backgroundPosition: '50px 50px' },
        },
      },
    },
  },
  plugins: [
    function({ addUtilities }) {
      addUtilities({
        '.glass': {
          background: 'rgba(17, 24, 39, 0.6)',
          backdropFilter: 'blur(12px) saturate(180%)',
          border: '1px solid rgba(30, 58, 95, 0.5)',
        },
        '.glass-strong': {
          background: 'rgba(17, 24, 39, 0.85)',
          backdropFilter: 'blur(20px) saturate(180%)',
          border: '1px solid rgba(30, 58, 95, 0.6)',
        },
        '.scanline': {
          position: 'relative',
        },
        '.scanline::after': {
          content: '""',
          position: 'absolute',
          inset: '0',
          background: 'repeating-linear-gradient(0deg, transparent, transparent 2px, rgba(0,0,0,0.15) 2px, rgba(0,0,0,0.15) 4px)',
          pointerEvents: 'none',
          zIndex: '50',
        },
        '.grid-bg': {
          backgroundImage: `
            linear-gradient(rgba(0,120,212,0.06) 1px, transparent 1px),
            linear-gradient(90deg, rgba(0,120,212,0.06) 1px, transparent 1px)
          `,
          backgroundSize: '50px 50px',
        },
        '.hex-pattern': {
          backgroundImage: `url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='28' height='49' viewBox='0 0 28 49'%3E%3Cg fill-rule='evenodd'%3E%3Cg fill='%230078D4' fill-opacity='0.03'%3E%3Cpath d='M13.99 9.25l13 7.5v15l-13 7.5L1 31.75v-15l12.99-7.5zM3 17.9v12.7l10.99 6.34 11-6.35V17.9l-11-6.34L3 17.9zM0 15l12.98-7.5V0h-2v6.35L0 12.69v2.3zm0 18.5L12.98 41v8h-2v-6.85L0 35.81v-2.3zM15 0v7.5L27.99 15H28v-2.31h-.01L17 6.35V0h-2zm0 49v-7.5L27.99 34H28v2.31h-.01L17 42.65V49h-2z'/%3E%3C/g%3E%3C/g%3E%3C/svg%3E")`,
        },
        '.text-glow': {
          textShadow: '0 0 10px rgba(0,120,212,0.5), 0 0 20px rgba(0,120,212,0.3)',
        },
        '.glow-bar-critical': {
          boxShadow: 'inset 4px 0 0 #ff3b3b, 0 0 15px rgba(255,59,59,0.2)',
        },
        '.glow-bar-high': {
          boxShadow: 'inset 4px 0 0 #ff8c42, 0 0 15px rgba(255,140,66,0.2)',
        },
        '.glow-bar-medium': {
          boxShadow: 'inset 4px 0 0 #ffc107, 0 0 15px rgba(255,193,7,0.2)',
        },
        '.glow-bar-low': {
          boxShadow: 'inset 4px 0 0 #00c853, 0 0 15px rgba(0,200,83,0.2)',
        },
        '.glow-bar-info': {
          boxShadow: 'inset 4px 0 0 #00b0ff, 0 0 15px rgba(0,176,255,0.2)',
        },
      })
    }
  ],
}
