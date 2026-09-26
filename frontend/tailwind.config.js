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
        cyber: {
          bg: "#080b11",
          card: "#0f172a",
          cardBorder: "#1e293b",
          primary: "#06b6d4",    // Cyan
          secondary: "#3b82f6",  // Blue
          critical: "#ef4444",   // Red
          high: "#f97316",       // Orange
          medium: "#eab308",     // Yellow
          low: "#3b82f6",        // Blue
          safe: "#10b981",       // Emerald
          darkText: "#94a3b8",
          glow: "rgba(6, 182, 212, 0.2)"
        }
      },
      fontFamily: {
        mono: ['JetBrains Mono', 'Fira Code', 'Courier New', 'monospace'],
        sans: ['Inter', 'system-ui', '-apple-system', 'sans-serif']
      }
    },
  },
  plugins: [],
}
