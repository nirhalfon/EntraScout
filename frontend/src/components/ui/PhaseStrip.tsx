import type { PhaseStatus } from '../../hooks/useScanEvents'

interface PhaseStripProps {
  phases: Record<string, PhaseStatus>
  totalPhases: number
}

const STATUS_CLASS: Record<string, string> = {
  running: 'bg-scout-accent animate-cell-pulse text-scout-accent',
  done: 'bg-scout-low/30 text-scout-low',
  error: 'bg-scout-critical/30 text-scout-critical',
  pending: 'bg-scout-border text-scout-muted-2',
}

export default function PhaseStrip({ phases, totalPhases }: PhaseStripProps) {
  const cells = Array.from({ length: totalPhases }, (_, i) => {
    const id = String(i + 1)
    const status = phases[id]?.status || 'pending'
    return (
      <div
        key={i}
        className={`h-[18px] flex items-center justify-center font-mono text-[8.5px] ${STATUS_CLASS[status] || 'bg-scout-border text-scout-muted-2'}`}
        title={`Phase ${id} — ${status}`}
      >
        {String(id).padStart(2, '0')}
      </div>
    )
  })

  return (
    <div className="bg-scout-panel border-b border-scout-border px-[18px] py-2">
      <div className="grid grid-cols-52 gap-[2px]" style={{ gridTemplateColumns: `repeat(${Math.min(totalPhases, 52)}, 1fr)` }}>
        {cells}
      </div>
    </div>
  )
}