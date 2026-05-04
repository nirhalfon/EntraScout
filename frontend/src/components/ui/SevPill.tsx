const SEV_MAP: Record<string, { fg: string; bg: string; border: string; label: string }> = {
  CRITICAL: { fg: 'var(--color-critical)', bg: 'oklch(0.30 0.10 25 / 0.25)', border: 'var(--color-critical)', label: 'CRIT' },
  HIGH:     { fg: 'var(--color-high)',     bg: 'oklch(0.28 0.09 55 / 0.22)', border: 'var(--color-high)',     label: 'HIGH' },
  MEDIUM:   { fg: 'var(--color-medium)',   bg: 'oklch(0.30 0.08 85 / 0.22)', border: 'var(--color-medium)',   label: 'MED' },
  LOW:      { fg: 'var(--color-low)',       bg: 'oklch(0.28 0.08 145 / 0.22)', border: 'var(--color-low)',     label: 'LOW' },
  INFO:     { fg: 'var(--color-info)',      bg: 'oklch(0.28 0.06 240 / 0.22)', border: 'var(--color-info)',    label: 'INFO' },
}

export default function SevPill({ sev }: { sev: string }) {
  const c = SEV_MAP[sev.toUpperCase()] || SEV_MAP.INFO
  return (
    <span style={{
      color: c.fg,
      background: c.bg,
      border: `1px solid ${c.border}`,
      padding: '1px 6px',
      borderRadius: 3,
      fontSize: 9.5,
      fontFamily: 'var(--font-mono, "JetBrains Mono", monospace)',
      letterSpacing: 0.5,
      fontWeight: 600,
    }}>
      {c.label}
    </span>
  )
}