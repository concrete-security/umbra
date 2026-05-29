/** @type {import('tailwindcss').Config} */
module.exports = {
  content: ["./static/admin/**/*.{html,js,svg}"],
  darkMode: "class",
  theme: {
    extend: {
      colors: {
        bg: "#0a0e14",
        surface: "#0f1620",
        panel: "#141c28",
        elev: "#1a2230",
        line: "#243042",
        "line-soft": "#1e2734",
        ink: "#e8eef6",
        "ink-dim": "#c8d4e3",
        mute: "#8b9cb3",
        "mute-soft": "#5d6c83",
        accent: {
          DEFAULT: "#6aa0f6",
          dim: "#3d6fad",
          glow: "#8fbafa",
          deep: "#1f3a66",
        },
        ok: { DEFAULT: "#46c37b", dim: "#1f6a3f", glow: "#7ed8a5" },
        warn: { DEFAULT: "#e6b84a", dim: "#7a5f1e", glow: "#f1ce75" },
        err: { DEFAULT: "#f07178", dim: "#7c2e34", glow: "#f59ba0" },
        info: { DEFAULT: "#7dd3fc", dim: "#1e5a7a" },
      },
      fontFamily: {
        sans: [
          "Inter",
          "ui-sans-serif",
          "system-ui",
          "-apple-system",
          "Segoe UI",
          "sans-serif",
        ],
        mono: [
          "JetBrains Mono",
          "SF Mono",
          "Cascadia Code",
          "Consolas",
          "ui-monospace",
          "monospace",
        ],
      },
      fontSize: {
        "2xs": ["0.6875rem", { lineHeight: "1rem" }],
        xs: ["0.75rem", { lineHeight: "1.1rem" }],
        sm: ["0.8125rem", { lineHeight: "1.25rem" }],
        base: ["0.9375rem", { lineHeight: "1.4rem" }],
        lg: ["1.0625rem", { lineHeight: "1.55rem" }],
        xl: ["1.25rem", { lineHeight: "1.65rem" }],
        "2xl": ["1.5rem", { lineHeight: "1.85rem" }],
        "3xl": ["1.875rem", { lineHeight: "2.15rem" }],
        stat: ["2.25rem", { lineHeight: "2.4rem", letterSpacing: "-0.03em" }],
        hero: ["2.75rem", { lineHeight: "2.95rem", letterSpacing: "-0.04em" }],
      },
      spacing: {
        "13": "3.25rem",
        "18": "4.5rem",
      },
      borderRadius: {
        card: "12px",
        input: "8px",
        pill: "999px",
      },
      boxShadow: {
        soft: "0 1px 2px rgba(0,0,0,0.25), 0 4px 14px rgba(0,0,0,0.3)",
        deep: "0 12px 40px rgba(0,0,0,0.45)",
        glow: "0 0 0 1px rgba(106,160,246,0.35), 0 8px 24px rgba(106,160,246,0.18)",
        "inner-soft": "inset 0 1px 0 rgba(255,255,255,0.04)",
      },
      backgroundImage: {
        "grad-hero":
          "radial-gradient(1200px 600px at 0% 0%, rgba(106,160,246,0.12), transparent 60%), radial-gradient(800px 400px at 100% 100%, rgba(70,195,123,0.08), transparent 60%)",
        "grad-tile":
          "linear-gradient(180deg, rgba(255,255,255,0.02) 0%, rgba(255,255,255,0) 100%)",
        "grad-stripe":
          "linear-gradient(135deg, rgba(106,160,246,0.06) 0%, rgba(106,160,246,0) 50%)",
      },
      animation: {
        "pulse-slow": "pulse 2.4s cubic-bezier(0.4,0,0.6,1) infinite",
        "fade-in": "fadeIn 0.18s ease-out",
        "slide-in": "slideIn 0.2s ease-out",
      },
      keyframes: {
        fadeIn: {
          "0%": { opacity: "0", transform: "translateY(-4px)" },
          "100%": { opacity: "1", transform: "none" },
        },
        slideIn: {
          "0%": { transform: "translateX(24px)", opacity: "0" },
          "100%": { transform: "none", opacity: "1" },
        },
      },
    },
  },
  plugins: [],
};
