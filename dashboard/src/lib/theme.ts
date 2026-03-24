/**
 * ThreatClaw Theme Tokens — single source of truth for all colors.
 *
 * Usage in inline styles:
 *   import { T } from '@/lib/theme'
 *   <div style={{ color: T.text, background: T.surface }}>
 *
 * All values are CSS var() references — they adapt to dark/light automatically.
 * To add a new theme: add a [data-theme="xxx"] block in globals.css.
 */

export const T = {
  // Backgrounds
  bg:           'var(--tc-bg)',
  surface:      'var(--tc-surface)',
  surfaceHover: 'var(--tc-surface-hover)',
  surfaceAlt:   'var(--tc-surface-alt)',
  input:        'var(--tc-input)',
  nav:          'var(--tc-nav)',

  // Text
  text:         'var(--tc-text)',
  textSec:      'var(--tc-text-sec)',
  textMuted:    'var(--tc-text-muted)',
  textFaint:    'var(--tc-text-faint)',

  // Borders
  border:       'var(--tc-border)',
  borderLight:  'var(--tc-border-light)',
  borderAccent: 'var(--tc-border-accent)',

  // Accent colors (don't change with theme)
  red:          'var(--tc-red)',
  redSoft:      'var(--tc-red-soft)',
  redBorder:    'var(--tc-red-border)',
  green:        'var(--tc-green)',
  greenSoft:    'var(--tc-green-soft)',
  amber:        'var(--tc-amber)',
  amberSoft:    'var(--tc-amber-soft)',
  blue:         'var(--tc-blue)',
  blueSoft:     'var(--tc-blue-soft)',
  purple:       'var(--tc-purple)',
  purpleSoft:   'var(--tc-purple-soft)',
  // Shapes
  radiusSm:    'var(--tc-radius-sm)',
  radiusMd:    'var(--tc-radius-md)',
  radiusLg:    'var(--tc-radius-lg)',
  radiusCard:  'var(--tc-radius-card)',
  radiusBtn:   'var(--tc-radius-btn)',
  radiusInput: 'var(--tc-radius-input)',
  radiusBadge: 'var(--tc-radius-badge)',
  radiusPill:  'var(--tc-radius-pill)',

  // Shadows
  shadowCard:  'var(--tc-shadow-card)',
  shadowHover: 'var(--tc-shadow-hover)',
  shadowInput: 'var(--tc-shadow-input)',
  shadowBtn:   'var(--tc-shadow-btn)',

  // Font sizes
  fontXs:      'var(--tc-font-xs)',
  fontSm:      'var(--tc-font-sm)',
  fontMd:      'var(--tc-font-md)',
  fontLg:      'var(--tc-font-lg)',
  fontXl:      'var(--tc-font-xl)',

  // Spacing
  spXs:        'var(--tc-space-xs)',
  spSm:        'var(--tc-space-sm)',
  spMd:        'var(--tc-space-md)',
  spLg:        'var(--tc-space-lg)',
  spXl:        'var(--tc-space-xl)',
} as const

/** Common style patterns reusable across components */
export const S = {
  card: {
    background: T.surface,
    border: `1px solid ${T.border}`,
    borderRadius: '12px',
    padding: '20px',
  } as React.CSSProperties,

  cardSm: {
    background: T.surface,
    border: `1px solid ${T.border}`,
    borderRadius: '10px',
    padding: '12px 14px',
  } as React.CSSProperties,

  input: {
    width: '100%',
    padding: '8px 10px',
    borderRadius: '8px',
    fontSize: '12px',
    background: T.input,
    border: `1px solid ${T.border}`,
    color: T.text,
    outline: 'none',
  } as React.CSSProperties,

  badge: (color: string, bg: string) => ({
    fontSize: '8px',
    fontWeight: 700,
    textTransform: 'uppercase' as const,
    padding: '2px 6px',
    borderRadius: '3px',
    background: bg,
    color: color,
    letterSpacing: '0.05em',
  }),

  sectionTitle: {
    fontSize: '13px',
    fontWeight: 700,
    textTransform: 'uppercase' as const,
    letterSpacing: '0.05em',
  } as React.CSSProperties,

  statBox: {
    textAlign: 'center' as const,
    padding: '14px',
    background: T.surface,
    border: `1px solid ${T.border}`,
    borderRadius: '10px',
  } as React.CSSProperties,

  btnPrimary: {
    display: 'flex',
    alignItems: 'center',
    gap: '6px',
    padding: '8px 16px',
    borderRadius: '8px',
    border: `1px solid ${T.redBorder}`,
    background: T.redSoft,
    color: T.red,
    fontSize: '11px',
    fontWeight: 600,
    cursor: 'pointer',
  } as React.CSSProperties,

  btnGhost: {
    display: 'flex',
    alignItems: 'center',
    gap: '6px',
    padding: '8px 16px',
    borderRadius: '8px',
    border: `1px solid ${T.border}`,
    background: T.surface,
    color: T.textMuted,
    fontSize: '11px',
    fontWeight: 600,
    cursor: 'pointer',
  } as React.CSSProperties,
}
