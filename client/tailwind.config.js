/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,jsx,ts,tsx}"],
  darkMode: "class",
  theme: {
    extend: {
      colors: {
        // Linear Dark Reference Tokens
        linear: {
          canvas: "#0B0C0E",
          sidebar: "#0E0F12",
          surface: "#141519",
          elevated: "#18191E",
          hover: "#1F2026",
          border: "rgba(255, 255, 255, 0.07)",
          borderSolid: "#222328",
          primary: "#EDEDED",
          secondary: "#8A8F98",
          tertiary: "#5F6368",
          accent: "#5E6AD2",
          accentHover: "#4F46E5",
        },
        // Backward-compatible semantic surface mappings
        base: "#0B0C0E",
        card: "#141519",
        surface: {
          50: "#0B0C0E",
          100: "#141519",
          200: "#18191E",
          300: "#222328",
          divider: "rgba(255, 255, 255, 0.07)",
        },
        border: {
          DEFAULT: "rgba(255, 255, 255, 0.07)",
          subtle: "#222328",
          hover: "rgba(255, 255, 255, 0.14)",
        },
        ink: {
          DEFAULT: "#EDEDED",
          title: "#F3F4F6",
          soft: "#8A8F98",
          mute: "#5F6368",
        },
        accent: {
          DEFAULT: "#5E6AD2",
          hover: "#4F46E5",
          violet: "#5E6AD2",
        },
        risk: {
          safe: "#34D399",
          low: "#34D399",
          medium: "#FBBF24",
          high: "#F87171",
        },
      },
      fontFamily: {
        sans: [
          '"Plus Jakarta Sans"',
          '"DM Sans"',
          '"General Sans"',
          "system-ui",
          "-apple-system",
          "BlinkMacSystemFont",
          '"Segoe UI"',
          "Roboto",
          "sans-serif",
        ],
        mono: [
          "Geist Mono",
          "JetBrains Mono",
          "ui-monospace",
          "monospace",
        ],
      },
      boxShadow: {
        panel: "0 0 0 1px rgba(255, 255, 255, 0.07), 0 2px 8px rgba(0, 0, 0, 0.3)",
        "panel-light": "0 0 0 1px rgba(0, 0, 0, 0.06), 0 1px 4px rgba(0, 0, 0, 0.04)",
      },
    },
  },
  plugins: [],
};
