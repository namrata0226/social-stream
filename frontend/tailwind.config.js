/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,jsx}"],
  theme: {
    extend: {
      colors: {
        // deep "night sky" neutrals with a hint of indigo
        ink: { 950: "#07070d", 900: "#0e0e18", 800: "#161624", 700: "#21212f", 600: "#2d2d40", 500: "#47475c" },
        brand: { DEFAULT: "#8b5cf6", hover: "#7c3aed", soft: "#c4b5fd" },
        glow: { DEFAULT: "#22d3ee", soft: "#a5f3fc" },
      },
      fontFamily: {
        sans: ["'Plus Jakarta Sans'", "system-ui", "sans-serif"],
        display: ["Outfit", "'Plus Jakarta Sans'", "system-ui", "sans-serif"],
      },
      keyframes: {
        fadeIn: { from: { opacity: 0 }, to: { opacity: 1 } },
        rise: { from: { opacity: 0, transform: "translateY(8px)" }, to: { opacity: 1, transform: "none" } },
        floatUp: {
          "0%": { opacity: 0, transform: "translateY(0) scale(.6)" },
          "15%": { opacity: 1, transform: "translateY(-20px) scale(1.15)" },
          "100%": { opacity: 0, transform: "translateY(-180px) scale(1)" },
        },
        pop: { "0%": { transform: "scale(1)" }, "40%": { transform: "scale(1.35)" }, "100%": { transform: "scale(1)" } },
      },
      animation: {
        fadeIn: "fadeIn .25s ease-out",
        rise: "rise .25s ease-out",
        floatUp: "floatUp 2.2s ease-out forwards",
        pop: "pop .3s ease-out",
      },
    },
  },
  plugins: [],
};
