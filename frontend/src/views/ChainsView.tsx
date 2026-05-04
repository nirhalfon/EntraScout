import Panel from '../components/ui/Panel'

interface ChainsViewProps {
  chain: any
  target: string
  findings: any[]
}

const EFFORT_STYLES: Record<string, { border: string; text: string }> = {
  low: { border: 'var(--color-high)', text: 'var(--color-high)' },
  medium: { border: 'var(--color-medium)', text: 'var(--color-medium)' },
  high: { border: 'var(--color-low)', text: 'var(--color-low)' },
}

export default function ChainsView({ chain, target }: ChainsViewProps) {
  const attackPaths = chain?.attack_paths || []
  const nodes = chain?.nodes || []

  return (
    <div className="flex flex-col gap-3.5">
      {/* SVG Graph */}
      <Panel title="ATTACK CHAIN GRAPH" sub="findings → chained primitives → MITRE ATT&CK">
        {nodes.length === 0 ? (
          <div className="relative">
            <svg width="100%" viewBox="0 0 880 360" style={{ display: 'block' }}>
              <defs>
                <pattern id="grid" width="20" height="20" patternUnits="userSpaceOnUse">
                  <path d="M 20 0 L 0 0 0 20" fill="none" stroke="#1c2433" strokeWidth="0.5" />
                </pattern>
              </defs>
              <rect width="880" height="360" fill="url(#grid)" />
              <text x="440" y="180" textAnchor="middle" fill="#4a5568" fontFamily="JetBrains Mono, monospace" fontSize="11">
                // attack chain graph idle — execute scan to populate
              </text>
            </svg>
          </div>
        ) : (
          <ChainGraph nodes={nodes} target={target} />
        )}
      </Panel>

      {/* Chain Detail Cards */}
      <Panel title="CHAIN DETAIL" sub={`${attackPaths.length} chains active`}>
        {attackPaths.length === 0 ? (
          <div className="py-6 text-scout-muted-2 italic font-mono text-[11px] text-center">// no chains derived — execute a scan with sufficient phases to populate</div>
        ) : (
          <div className="grid grid-cols-[repeat(auto-fill,minmax(360px,1fr))] gap-2.5">
            {attackPaths.map((path: any, i: number) => {
              const style = EFFORT_STYLES[path.effort] || EFFORT_STYLES.medium
              return (
                <div key={i} className="bg-scout-panel-2 border border-scout-border border-l-[3px] p-3 px-3.5" style={{ borderLeftColor: style.border }}>
                  <div className="flex flex-col gap-1 mb-2">
                    <div className="text-[13.5px] font-semibold text-scout-text">{path.name}</div>
                    <div className="flex gap-3 font-mono text-[9.5px] tracking-wide">
                      <span style={{ color: style.text }}>EFFORT · {String(path.effort).toUpperCase()}</span>
                      <span className="text-scout-muted">{(path.mitre || []).join(' · ')}</span>
                    </div>
                  </div>
                  <div className="font-mono text-[10.5px] text-scout-muted mb-2 pb-2 border-b border-dashed border-scout-border">
                    {path.blast_radius || path.blast || ''}
                  </div>
                  {path.story && (
                    <ol className="mb-2 pl-[18px] text-[11.5px] text-scout-text leading-relaxed list-decimal">
                      {path.story.map((s: string, j: number) => <li key={j} className="py-0.5">{s}</li>)}
                    </ol>
                  )}
                  {path.tags && (
                    <div className="flex flex-wrap gap-1">
                      {path.tags.map((t: string) => <span key={t} className="font-mono text-[9px] bg-scout-border text-scout-muted px-1.5 py-0.5 rounded-sm tracking-wide">{t}</span>)}
                    </div>
                  )}
                </div>
              )
            })}
          </div>
        )}
      </Panel>
    </div>
  )
}

function ChainGraph({ nodes, target }: { nodes: any[]; target: string }) {
  const W = 880, H = 360
  const targetX = 90, targetY = H / 2

  const pathNodes = nodes.filter((n: any) => n.label?.includes('→') || n.severity === undefined)

  return (
    <svg width="100%" viewBox={`0 0 ${W} ${H}`} style={{ display: 'block' }}>
      <defs>
        <pattern id="grid2" width="20" height="20" patternUnits="userSpaceOnUse">
          <path d="M 20 0 L 0 0 0 20" fill="none" stroke="#1c2433" strokeWidth="0.5" />
        </pattern>
      </defs>
      <rect width={W} height={H} fill="url(#grid2)" />

      {/* Target node */}
      <circle cx={targetX} cy={targetY} r="48" fill="oklch(0.18 0.05 220 / 0.3)" />
      <circle cx={targetX} cy={targetY} r="14" fill="var(--color-accent)" />
      <text x={targetX} y={targetY + 70} textAnchor="middle" fill="#c9d1d9" fontFamily="JetBrains Mono, monospace" fontSize="10">{target || 'target'}</text>

      {/* Path cards */}
      {pathNodes.slice(0, 6).map((n: any, i: number) => {
        const angle = ((i / Math.max(1, pathNodes.length - 1)) - 0.5) * 1.4
        const cx = 700, cy = H / 2 + angle * (H / 2 - 40)
        const sevColor = n.severity === 'HIGH' ? 'var(--color-high)' : n.severity === 'CRITICAL' ? 'var(--color-critical)' : 'var(--color-info)'
        const path = `M ${targetX + 12} ${targetY} C ${(targetX + cx) / 2} ${targetY}, ${(targetX + cx) / 2} ${cy}, ${cx - 130} ${cy}`
        return (
          <g key={i}>
            <path d={path} stroke={sevColor} strokeWidth="1.2" fill="none" opacity="0.55" strokeDasharray="3 3">
              <animate attributeName="strokeDashoffset" from="0" to="-12" dur="1.2s" repeatCount="indefinite" />
            </path>
            <g transform={`translate(${cx - 130}, ${cy - 28})`}>
              <rect width="220" height="56" fill="#0f1521" stroke={sevColor} strokeWidth="1" rx="2" />
              <rect x="0" y="0" width="3" height="56" fill={sevColor} />
              <text x="12" y="16" fill="#c9d1d9" fontFamily="Inter, sans-serif" fontSize="11" fontWeight="600">{(n.label || n.tag || '').length > 28 ? (n.label || n.tag || '').slice(0, 27) + '…' : n.label || n.tag}</text>
              <text x="12" y="46" fill="#8b949e" fontFamily="JetBrains Mono, monospace" fontSize="8.5">{(n.mitre || []).join(' · ')}</text>
            </g>
          </g>
        )
      })}
    </svg>
  )
}