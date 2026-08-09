# RingZero Design System

RingZero is a Linux eBPF security command center. The interface is a calm,
watchful instrument panel: it should feel precise, quiet and trustworthy at
rest, and unmistakably urgent under threat.

## 1. Principles

1. **Calm by default.** The resting UI is low-contrast and quiet. Color is
   reserved for meaning, never decoration.
2. **Data density without noise.** Tables and live feeds are dense but
   evenly spaced. Every row earns its pixel.
3. **Semantic color > decorative color.** Green is never "pretty" — it means
   *protected*. Red never means "brand" — it means *threat*.
4. **Theme-native.** Every surface, text and border is a semantic token, not
   a hard-coded hex. Dark and light are first-class citizens; the OS theme is
   respected and a manual override exists.

## 2. Color tokens

Two themes share one semantic token set. **Never hard-code colors in
components** — reference tokens so theme switching is a single flip.

### Core surfaces

| Token | Dark | Light | Use |
|---|---|---|---|
| `bg.base` | `#0d1117` | `#f6f8fa` | window background |
| `bg.surface` | `#161b22` | `#ffffff` | cards, panels |
| `bg.surfaceAlt` | `#21262d` | `#f0f3f6` | headers, alternating rows |
| `bg.input` | `#0d1117` | `#ffffff` | fields, embedded areas |
| `bg.hover` | `#2a3038` | `#eaeef2` | hover states |
| `bg.overlay` | `#0d1117e6` | `#f6f8fae6` | modal scrims |

### Borders & separators

| Token | Dark | Light |
|---|---|---|
| `border.default` | `#30363d` | `#d1d9e0` |
| `border.strong` | `#3d444d` | `#b6c2cc` |
| `divider` | `#21262d` | `#e1e6eb` |

### Text

| Token | Dark | Light | Use |
|---|---|---|---|
| `text.primary` | `#e6edf3` | `#1f2328` | main content |
| `text.secondary` | `#8b949e` | `#59636e` | labels, timestamps |
| `text.muted` | `#6e7681` | `#8c959f` | disabled, footers |
| `text.onAccent` | `#0d1117` | `#ffffff` | text on accent fills |

### Semantic accents

| Token | Dark | Light | Meaning |
|---|---|---|---|
| `accent.info` | `#58a6ff` | `#0969da` | network, neutral info |
| `accent.success` | `#3fb950` | `#1a7f37` | protected, trusted, allowed |
| `accent.warning` | `#d29922` | `#9a6700` | degraded, caution |
| `accent.danger` | `#f85149` | `#d1242f` | threat, blocked, denied |
| `accent.purple` | `#bc8cff` | `#8250df` | DPI, DNS, security analytics |

**Severity mapping** (used by every alert/badge):
`CRITICAL → danger` · `HIGH → warning` · `MED → purple` · `LOW → muted`.

## 3. Typography

- **Stack**: `Inter, "SF Pro Text", system-ui, sans-serif` (system fallback).
- Scale (px): 10 (micro labels) · 11 (metadata) · 12 (body) · 14 (emphasis) ·
  16 (section titles) · 20 (stat values).
- Weights: 400 (body), 600 (emphasis), 700 (stat/display).
- Numeric data uses tabular figures where available (stats, pids, ports).
- Line-height: 1.4 for body, 1.2 for headings.

## 4. Spacing & layout

- **4px grid**: 4 / 8 / 12 / 16 / 24 / 32.
- Card padding: 12px. Card corner: 6px radius, 1px border.
- Stat tiles: 12px padding, 52–80px tall, value 20px bold on a 9px label.
- Table row: 20–24px tall, 8px horizontal padding, alternate `surfaceAlt`
  striping, `divider` between sections.
- Feed/event rows: 22px tall with a 46px severity pill.

## 5. Radius & elevation

- Radius: 4 (inputs, pills) · 6 (cards, tables) · 8 (prompt window, icons) ·
  12 (dialogs).
- Elevation is border-based (1px `border.default`); shadows only for
  modals/popups: `0 8px 24px rgba(0,0,0,.25)` dark / `0 4px 16px
  rgba(31,35,40,.12)` light.

## 6. Components

### Cards
`bg.surface` + 1px `border.default` + radius 6 + 12px padding. Titles 16px
`accent.info`.

### Stat tiles
`bg.surface` or `bg.surfaceAlt`, centered value + label. Value colored by
meaning (never `accent.info` for a danger stat).

### Severity pill (badge)
46 × 12px, radius 3, 8px bold text in `text.onAccent` on the severity color.
Used in event feeds and alert rows.

### Buttons
- **Primary**: `accent.info` fill, `text.onAccent`, 28px tall, radius 6.
- **Danger**: `accent.danger` fill for destructive/block actions.
- **Flat**: transparent, `text.secondary`, hover `bg.hover`.
- 12px labels, 600 weight.

### Tabs
TabBar with 12px labels; active tab `bg.surfaceAlt` + 1px `border.strong`
bottom edge; inactive transparent.

### Progress / countdown
Bar: 4px tall, radius 2. Fill = `accent.info` above 5s, `accent.warning`
3–5s, `accent.danger` below 3s. Fill width MUST bind to `visualPosition`.

### Charts
1px lines in semantic accent on `bg.input`. Axis-less; labels only.

### Modals (alerts, prompts)
`bg.surface`, radius 12, 1px `border.strong`, centered. Scrim:
`bg.overlay`. Emergency header 16px `accent.danger` bold.

## 7. Iconography

Geometric text glyphs only (no emoji):
`●` status dot · `◐` activity · `↑` egress · `↓` ingress · `✕` close ·
`🛡` is replaced by a solid shield drawn as text `◈` or the wordmark.
The wordmark is **RingZero** in 600 weight with a cyan `◈` mark.

## 8. Theme system

- **Modes**: `dark`, `light`, `system`.
- `system` resolves via `Qt.styleHints.colorScheme` (Dark/Light) and
  re-evaluates when the OS theme changes.
- The active mode is persisted (Qt `Settings`) and exposed as a toggle
  (Dark / Light / System) in the Settings view.
- All components read the `Theme` singleton; a mode change flips every token
  in one frame.

## 9. Motion

- Micro only: 120ms ease-out for hovers, 150ms for popup fade/scale.
- No infinite animation outside live data (charts, countdown).
- Threat transitions (Protected → Threat) use a 200ms color pulse.

## 10. Do / don't

- **Do** use semantic tokens everywhere. **Don't** hard-code hex in views.
- **Do** reserve red for genuine threats. **Don't** use it for branding.
- **Do** keep resting contrast low. **Don't** add decorative gradients.
- **Do** keep rows dense and aligned. **Don't** crowd controls into feeds.
