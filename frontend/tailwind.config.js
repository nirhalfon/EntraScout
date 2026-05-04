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
          bg: '#0d1117',
          panel: '#161b22',
          border: '#30363d',
          muted: '#8b949e',
          text: '#c9d1d9',
          accent: '#58a6ff',
          critical: '#f85149',
          high: '#ff7b72',
          medium: '#d29922',
          low: '#56d364',
          info: '#58a6ff',
        }
      }
    },
  },
  plugins: [],
}
