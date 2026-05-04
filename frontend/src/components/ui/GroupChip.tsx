const GROUP_META: Record<string, { label: string; hue: number }> = {
  identity:  { label: 'IDENTITY',  hue: 220 },
  m365:      { label: 'M365',       hue: 280 },
  azure:     { label: 'AZURE',      hue: 200 },
  power:     { label: 'POWER',      hue: 320 },
  defense:   { label: 'DEFENSE',    hue: 0 },
  dns:       { label: 'DNS',        hue: 150 },
  osint:     { label: 'OSINT',      hue: 75 },
  endpoint:  { label: 'ENDPOINT',  hue: 175 },
  internal:  { label: 'INTERNAL',  hue: 50 },
}

export default function GroupChip({ group }: { group: string }) {
  const meta = GROUP_META[group] || { label: group.toUpperCase(), hue: 220 }
  return (
    <span style={{
      color: `oklch(0.78 0.10 ${meta.hue})`,
      background: `oklch(0.20 0.04 ${meta.hue})`,
      padding: '1px 5px',
      borderRadius: 2,
      fontSize: 9,
      fontFamily: '"JetBrains Mono", monospace',
      letterSpacing: 0.6,
    }}>
      {meta.label}
    </span>
  )
}