interface SevBarsProps {
  counts: Record<string, number>
}

const ORDER = ['critical', 'high', 'medium', 'low', 'info'] as const
const LABELS: Record<string, string> = { critical: 'CRITICAL', high: 'HIGH', medium: 'MEDIUM', low: 'LOW', info: 'INFO' }
const COLORS: Record<string, string> = {
  critical: 'var(--color-critical)',
  high: 'var(--color-high)',
  medium: 'var(--color-medium)',
  low: 'var(--color-low)',
  info: 'var(--color-info)',
}

export default function SevBars({ counts }: SevBarsProps) {
  const max = Math.max(1, ...ORDER.map(s => counts[s] || 0))
  return (
    <div className="flex flex-col gap-1.5">
      {ORDER.map(s => (
        <div key={s} className="grid grid-cols-[80px_1fr_32px] gap-2.5 items-center font-mono text-[10px]">
          <span className="tracking-widest font-bold" style={{ color: COLORS[s] }}>{LABELS[s]}</span>
          <div className="bg-scout-border h-2 rounded-sm overflow-hidden">
            <div className="h-full transition-all duration-400" style={{ width: `${((counts[s] || 0) / max) * 100}%`, background: COLORS[s] }} />
          </div>
          <span className="text-right tabular-nums text-scout-text">{counts[s] || 0}</span>
        </div>
      ))}
    </div>
  )
}