# Confidential AI Visual System — October 2025 Refresh

The following spec captures the updated marketing surface shown in the latest brand reference. The system leans into a neutral gray field, bold black typography, and saturated purple accents. Treat this as the single source of truth when implementing or evaluating UI for the landing experience.

---

## Brand Identity

- **Product name:** Confidential AI  
- **Tagline:** “Confidential AI for sensitive data — security, privacy, confidentiality backed by modern cryptography.”
- **Tone:** Precise, trustworthy, and modern. Emphasis on clarity over flourish.

---

## Color Palette

| Token | Hex | Usage |
| --- | --- | --- |
| `--surface-cloud` | `#E2E2E2` | Page background, section fills, cards |
| `--ink-onyx` | `#08070B` | Primary text, nav items, solid CTA background |
| `--ink-mid` | `#1F1E28` | Secondary text, paragraph copy |
| `--accent-royal` | `#1B0986` | Accent text (the “AI” wordmark), outline CTA, decorative swatches |
| `--accent-royal-dark` | `#0B0870` | Deep gradient stop, gradient cards, hero art shadows |
| `--accent-lavender` | `#C9C6F5` | Soft glow overlays, button focus ring, gradient halos |
| `--base-white` | `#FFFFFF` | Card fills, buttons, icons |

> Accessibility target: Maintain AA contrast between any foreground text and `--surface-cloud` or gradient overlays. Use `--ink-onyx` for anything over neutral backgrounds, and bump to `--base-white` when text overlays gradients.

---

## Gradient Library

1. **Hero Art Gradient (square tile):**
   ```css
   background: linear-gradient(211.15deg, rgba(0, 0, 0, 0) 18.84%, rgba(0, 0, 0, 0.2) 103.94%);
   ```
2. **Hero Surface Glow (under cards / dividers):**
   ```css
   background: radial-gradient(120% 60% at 50% 0%, rgba(205, 199, 247, 0.45) 0%, rgba(205, 199, 247, 0.2) 42%, rgba(205, 199, 247, 0) 100%);
   ```
3. **Gradient Card (who-we-are grid, rightmost tile is solid):**
   ```css
   background: linear-gradient(231.82deg, rgba(226, 226, 226, 0.2) 8.09%, rgba(27, 9, 134, 0.2) 105.85%);
   ```
4. **Inset Lavender Panel (hero behind gradient square):**
   ```css
   background: linear-gradient(200deg, rgba(242, 241, 255, 0.65) 0%, rgba(201, 198, 245, 0.08) 60%, rgba(201, 198, 245, 0) 100%);
   ```

---

## Typography

| Element | Font | Weight | Size / Line Height | Notes |
| --- | --- | --- | --- | --- |
| Navigation items | “Telegraf”, sans-serif | 500 | 16px / 22px | Letter-spacing 0.02em |
| Hero eyebrow | Telegraf | 600 | 16px / 22px | Uppercase, tracking 0.16em |
| Hero heading | Telegraf | 700 | 64px / 68px | "Confidential" in `--ink-onyx`, "AI" in `--accent-royal` |
| Body copy | Telegraf | 400 | 18px / 28px | `--ink-mid` color |
| Section headings | Telegraf | 700 | 40px / 48px | Left aligned, stacked phrases |
| Caption / label | Telegraf | 600 | 14px / 20px | Used for feature titles |

Fallback stack: `Telegraf, "Inter", "Roboto", "Helvetica Neue", Arial, sans-serif`.

---

## Components

### 1. Navigation Bar
- **Height:** 72px  
- **Container:** 1200px max-width, centered, 32px horizontal padding on smaller screens  
- **Left:** Dot-matrix Confidential AI logo (48px width)  
- **Center:** Menu items spaced 32px apart  
- **Right:** Primary CTA (solid black pill), secondary CTA (outlined)

```css
.nav-cta-primary {
  display: inline-flex;
  align-items: center;
  gap: 8px;
  padding: 12px 20px;
  border-radius: 999px;
  background: #08070B;
  color: #FFFFFF;
  font-weight: 600;
  box-shadow: 0 14px 28px -16px rgba(15, 11, 56, 0.65);
}

.nav-cta-secondary {
  display: inline-flex;
  align-items: center;
  padding: 12px 20px;
  border-radius: 999px;
  border: 1px solid #1B0986;
  color: #1B0986;
  font-weight: 600;
  background: transparent;
}
```

### 2. Hero Section

Layout is a two-column split (60/40) constrained to 1200px:

- **Left column:** Eyebrow, display heading, body copy (max-width 360px), CTA row.  
- **CTA row:** Primary (black) + Secondary (outline) with 16px gap. Primary includes right arrow icon (16px).  
- **Right column:** Stacked art — a lavender panel (`inset panel`) offset with a hero gradient square (320px x 320px). The square slightly overlaps the panel (12px left shift, 28px down).  
- **Background:** Section uses `--surface-cloud` with a subtle top glow from the hero surface gradient.

### 3. Feature Trio (Security, Privacy, IP Protection)

- Section top margin 96px from hero.  
- Headline is left-aligned, multi-line.  
- Supporting paragraph width 520px.  
- Feature row: three columns, each 260px wide with a 48px gap.  
- Each card includes:
  - 32px square filled with `--accent-royal`.  
  - Label in uppercase weight 600.  
  - Body text 16px / 24px, `--ink-mid`.

### 4. Divider Glow

Between feature section and “Who we are” add a 100% width, 12px tall lavender blur:

```css
.section-divider {
  height: 140px;
  background: radial-gradient(120% 60% at 50% 0%, rgba(205, 199, 247, 0.32) 0%, rgba(205, 199, 247, 0) 80%);
  filter: blur(0.5px);
}
```

### 5. Who We Are Section

- Heading + paragraph similar to previous section.  
- Card grid: three 260px squares with 36px gap.  
- Card backgrounds:
  1. Left tile: lavender-to-white gradient (hero surface glow).  
  2. Middle tile: primary gradient `linear-gradient(231.82deg, rgba(226, 226, 226, 0.2) 8.09%, rgba(27, 9, 134, 0.2) 105.85%)`.  
  3. Right tile: solid `#1B0986`.  
- Cards have 20px border radius, drop shadow: `0 32px 78px -64px rgba(15, 10, 80, 0.65)`.

---

## Spacing System

- **Section gap:** 120px top / 88px bottom  
- **Grid gutter:** 36px  
- **Hero CTA gap:** 16px  
- **Paragraph spacing:** 18px (margin-bottom)  
- **Nav horizontal padding:** 32px (24px on ≤ 768px)

---

## Layout Breakpoints

- **Desktop (≥1280px):** Maintain the two-column hero and three-column grids.  
- **Tablet (768–1279px):** Stack hero columns with art centered below text; feature trio collapses to two columns.  
- **Mobile (<768px):** Stack all blocks vertically, hero heading drops to 40px, CTA buttons expand to full width, cards follow single column with 24px spacing.

---

## Interaction Guidelines

- **Primary CTA hover:** Slight scale (1.02) and raise brightness of black background to `#111015`.  
- **Outline CTA hover:** Fill with `#1B0986`, change text to `#FFFFFF`, drop subtle shadow `0 12px 24px -16px rgba(27, 9, 134, 0.38)`.
- **Focus states:** Use 2px outline in `--accent-lavender` for both buttons and links.  
- **Links in body copy:** Underline-only on hover, default color `--ink-onyx`.

---

## Asset Notes

- **Logo:** Monochrome dot-matrix mark, 48px width, align baseline with nav copy.  
- **Icons:** Flat monochrome (black or white).  
- **Gradients:** Render using CSS where possible; for illustrative hero art, use the provided gradient definitions and overlay a subtle, repeating binary pattern (4px dot spacing, 10% opacity) to mirror the reference.

---

## Implementation Checklist

1. Apply `--surface-cloud` to `<body>` and ensure containers sit on pure white to create depth.  
2. Split hero into a responsive grid with a 64px gap.  
3. Use the gradient library exactly as defined for hero art and the “Who we are” cards.  
4. Use `#1B0986` for accents and apply the updated gradient stops where specified.  
5. Maintain consistent drop shadows: hero buttons and gradient cards share the same soft navy shadow recipe.

This template supersedes previous Confidential AI marketing specs. Always cross-check new layouts against this document before implementation.
