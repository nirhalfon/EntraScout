import { useState, useMemo } from 'react'
import type { Finding } from '../hooks/useScanEvents'
import Panel from '../components/ui/Panel'
import SevPill from '../components/ui/SevPill'
import GroupChip from '../components/ui/GroupChip'

interface FindingsViewProps {
  findings: Finding[]
  counts: Record<string, number>
}

const SEVS = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'] as const

export default function FindingsView({ findings, counts }: FindingsViewProps) {
  const [filter, setFilter] = useState<string>('all')

  const filtered = useMemo(() => {
    if (filter === 'all') return findings
    return findings.filter(f => f.severity.toUpperCase() === filter)
  }, [findings, filter])

  return (
    <div>
      <Panel title="FINDINGS" sub={`${findings.length} total · filterable`}>
        <div className="flex flex-col">
          <div className="flex gap-1 p-1 bg-scout-panel-2 border-b border-scout-border">
            <button onClick={() => setFilter('all')} className={`bg-transparent border px-2.5 py-1 font-mono text-[10px] tracking-wider font-semibold flex items-center gap-1.5 ${filter === 'all' ? 'border-scout-border-2 bg-scout-bg text-scout-text' : 'border-transparent text-scout-muted hover:text-scout-text'}`}>
              ALL <span className="tabular-nums">{findings.length}</span>
            </button>
            {SEVS.map(s => (
              <button key={s} onClick={() => setFilter(s)} className={`bg-transparent border px-2.5 py-1 font-mono text-[10px] tracking-wider font-semibold flex items-center gap-1.5 ${filter === s ? 'border-scout-border-2 bg-scout-bg text-scout-text' : 'border-transparent text-scout-muted hover:text-scout-text'}`}>
                <SevPill sev={s} />
                <span className="tabular-nums">{counts[s] || 0}</span>
              </button>
            ))}
          </div>
          <div className="max-h-[540px] overflow-y-auto scrollbar-thin">
            {filtered.map((f, i) => (
              <div key={f.id || i} className="grid grid-cols-[200px_1fr_140px] gap-3.5 px-3.5 py-2.5 border-b border-scout-border hover:bg-scout-accent/5 items-start max-[1024px]:grid-cols-1">
                <div className="flex items-center gap-2 flex-wrap">
                  <SevPill sev={f.severity} />
                  <span className="font-mono text-[9.5px] text-scout-muted tracking-wide">{f.tags?.[0] || f.check}</span>
                </div>
                <div>
                  <div className="text-[12.5px] font-semibold text-scout-text mb-0.5">{f.title}</div>
                  <div className="font-mono text-[11px] text-scout-muted break-words">{f.description}</div>
                </div>
                <div className="flex items-center gap-2 justify-end max-[1024px]:justify-start">
                  <GroupChip group={f.phase} />
                  <span className="font-mono text-[9.5px] text-scout-muted-2">P{String(f.phase).padStart(2, '0')}</span>
                </div>
              </div>
            ))}
            {filtered.length === 0 && (
              <div className="py-6 text-scout-muted-2 italic font-mono text-[11px] text-center">// no findings at this severity yet</div>
            )}
          </div>
        </div>
      </Panel>
    </div>
  )
}