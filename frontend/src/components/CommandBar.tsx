import { useState, useEffect } from 'react'
import { usePhases } from '../hooks/useScanEvents'

interface CommandBarProps {
  onSubmit: (target: string, options: Record<string, unknown>) => void
  loading: boolean
  onCancel: () => void
}

const SAMPLE_TARGETS = ['contoso.com', 'fabrikam.io', 'northwind-traders.com', 'adatum.corp', 'wingtiptoys.com']

export default function CommandBar({ onSubmit, loading, onCancel }: CommandBarProps) {
  const [target, setTarget] = useState('')
  const [stealth, _setStealth] = useState(false)
  const [showPhases, setShowPhases] = useState(false)
  const [selectedPhases, setSelectedPhases] = useState<Set<string>>(new Set())
  const phases = usePhases()

  useEffect(() => {
    if (phases.length > 0 && selectedPhases.size === 0) {
      setSelectedPhases(new Set(phases.map(p => p.id)))
    }
  }, [phases.length])

  const handleSubmit = () => {
    if (!target.trim()) return
    onSubmit(target.trim(), {
      target: target.trim(),
      phases: Array.from(selectedPhases),
      stealth,
    })
  }

  const togglePhase = (id: string) => {
    const next = new Set(selectedPhases)
    if (next.has(id)) next.delete(id); else next.add(id)
    setSelectedPhases(next)
  }

  return (
    <div>
      <section className="flex items-center gap-2.5 px-[18px] py-3 bg-scout-panel border-b border-scout-border font-mono text-[12.5px]">
        <span className="text-scout-accent font-bold">$</span>
        <span className="text-scout-text font-semibold">scout</span>
        <input
          value={target}
          onChange={e => setTarget(e.target.value)}
          onKeyDown={e => e.key === 'Enter' && !loading && handleSubmit()}
          disabled={loading}
          placeholder="target.com"
          className="flex-[0_1_320px] bg-transparent border-b border-scout-border-2 text-scout-text font-mono text-[13px] px-1.5 py-1 outline-none focus:border-scout-accent placeholder:text-scout-muted-2 placeholder:italic"
        />
        <span className="text-scout-muted text-[10.5px] tracking-wide flex-1">
          --phases <strong className="text-scout-text">{selectedPhases.size}/{phases.length || 52}</strong>
          {stealth && <span className="text-scout-low"> · --stealth</span>}
        </span>
        <div className="flex gap-1.5">
          <button onClick={() => setShowPhases(v => !v)} className="bg-transparent border border-scout-border-2 text-scout-muted px-3 py-[5px] text-[10.5px] tracking-widest font-semibold hover:text-scout-text hover:border-scout-muted transition-colors cursor-pointer">
            {showPhases ? '↑ phases' : '↓ phases'}
          </button>
          <button onClick={() => setTarget(SAMPLE_TARGETS[Math.floor(Math.random() * SAMPLE_TARGETS.length)])} className="bg-transparent border border-scout-border-2 text-scout-muted px-3 py-[5px] text-[10.5px] tracking-widest font-semibold hover:text-scout-text hover:border-scout-muted transition-colors cursor-pointer">
            random
          </button>
          {loading ? (
            <button onClick={onCancel} className="bg-transparent border border-scout-high text-scout-high px-3 py-[5px] text-[10.5px] tracking-widest font-semibold hover:bg-scout-high/10 transition-colors cursor-pointer">
              ■ cancel
            </button>
          ) : (
            <button onClick={handleSubmit} disabled={!target.trim()} className="bg-transparent border border-scout-accent text-scout-accent px-3 py-[5px] text-[10.5px] tracking-widest font-semibold hover:bg-scout-accent/10 hover:shadow-[0_0_14px_oklch(0.50_0.12_220/0.4)] disabled:opacity-35 disabled:cursor-not-allowed transition-colors cursor-pointer">
              ▶ execute
            </button>
          )}
        </div>
      </section>

      {showPhases && (
        <section className="bg-scout-panel border-b border-scout-border px-[18px] py-2.5 pb-3.5">
          <div className="flex gap-1.5 items-center mb-2.5 font-mono text-[10.5px]">
            <button onClick={() => setSelectedPhases(new Set(phases.map(p => p.id)))} className="bg-transparent border border-scout-border-2 text-scout-muted px-2 py-1 text-[10.5px] tracking-wide font-semibold hover:text-scout-text hover:border-scout-muted transition-colors cursor-pointer">all</button>
            <button onClick={() => setSelectedPhases(new Set())} className="bg-transparent border border-scout-border-2 text-scout-muted px-2 py-1 text-[10.5px] tracking-wide font-semibold hover:text-scout-text hover:border-scout-muted transition-colors cursor-pointer">none</button>
            <button onClick={() => setSelectedPhases(new Set(['1','2','3','4','5','6','7','8','9','10','11','12','13','14']))} className="bg-transparent border border-scout-border-2 text-scout-muted px-2 py-1 text-[10.5px] tracking-wide font-semibold hover:text-scout-text hover:border-scout-muted transition-colors cursor-pointer">quick</button>
            <span className="text-scout-muted ml-auto">{selectedPhases.size} of {phases.length || 52} phases enabled</span>
          </div>
          <div className="grid grid-cols-[repeat(auto-fill,minmax(220px,1fr))] gap-1">
            {phases.map(p => {
              const on = selectedPhases.has(p.id)
              return (
                <button key={p.id} onClick={() => togglePhase(p.id)} className={`flex items-center gap-2 px-2 py-[5px] bg-transparent border text-scout-text font-mono text-[10.5px] text-left transition-colors cursor-pointer ${on ? 'border-scout-border-2 bg-scout-accent/5' : 'border-scout-border opacity-40 hover:border-scout-accent'}`}>
                  <span className="text-scout-muted text-[9.5px] tabular-nums w-[18px]">{String(p.id).padStart(2, '0')}</span>
                  <span className="flex-1">{p.name}</span>
                </button>
              )
            })}
          </div>
        </section>
      )}
    </div>
  )
}