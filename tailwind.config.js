/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    "./src/pages/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/components/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/app/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  darkMode: "class",
  theme: {
    extend: {
      colors: {
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
      },
    },
  },
  plugins: [],
};
