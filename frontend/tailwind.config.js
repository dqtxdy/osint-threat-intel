/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        ink: "#f6f8fb",
        panel: "#ffffff",
        panel2: "#eef3f8",
        line: "#d8e0ea",
        cyanx: "#0369a1",
        tealt: "#0f766e",
        amberx: "#b45309",
        danger: "#dc2626"
      },
      boxShadow: {
        glow: "0 1px 2px rgba(15,23,42,0.06), 0 18px 45px rgba(15,23,42,0.08)"
      }
    },
  },
  plugins: [],
};
