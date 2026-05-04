import type { Finding } from '../hooks/useScanEvents'
import SevPill from '../components/ui/SevPill'

const GROUP_META: Record<string, { label: string; hue: number; phases: string[] }> = {
  identity:  { label: 'IDENTITY',  hue: 220, phases: ['1','2','3','14','17','23','43'] },
  m365:      { label: 'M365',       hue: 280, phases: ['4','44','45'] },
  azure:     { label: 'AZURE',      hue: 200, phases: ['13','16','29','30','38','39','40','48'] },
  power:     { label: 'POWER',      hue: 320, phases: ['11','12','50'] },
  defense:   { label: 'DEFENSE',    hue: 0,   phases: ['8','26','31','33','34','46'] },
  dns:       { label: 'DNS',        hue: 150, phases: ['5','35'] },
  osint:     { label: 'OSINT',      hue: 75,  phases: ['10','15','18','24','27','28','47'] },
  endpoint:  { label: 'ENDPOINT',  hue: 175, phases: ['22','37','41'] },
}

interface SurfaceViewProps {
  findings: Finding[]
}

export default function SurfaceView({ findings }: SurfaceViewProps) {
  // Group findings by phase -> group mapping
  const byGroup: Record<string, Finding[]> = {}
  for (const f of findings) {
    // Find which group this finding's phase belongs to
    let group = 'identity'
    for (const [g, meta] of Object.entries(GROUP_META)) {
      if (meta.phases.includes(f.phase)) {
        group = g
        break
      }
    }
    if (!byGroup[group]) byGroup[group] = []
    byGroup[group].push(f)
  }

  const groups = Object.keys(GROUP_META).filter(g => byGroup[g]?.length)

  return (
    <div className="grid grid-cols-[repeat(auto-fill,minmax(280px,1fr))] gap-2.5">
      {groups.map(g => {
        const meta = GROUP_META[g]
        const items = byGroup[g] || []
        return (
          <div key={g} className="bg-scout-panel border border-scout-border p-2.5 px-3" style={{ borderColor: `oklch(0.40 0.06 ${meta.hue})` }}>
            <div className="flex justify-between items-center font-mono tracking-widest text-[10.5px] font-bold mb-2 pb-1.5 border-b border-scout-border" style={{ color: `oklch(0.78 0.10 ${meta.hue})` }}>
              <span>{meta.label}</span>
              <span className="tabular-nums">{items.length}</span>
            </div>
            <div className="flex flex-col gap-1 min-h-[80px]">
              {items.length === 0 && <div className="font-mono text-[10px] text-scout-muted-2 italic">— no signal —</div>}
              {items.slice(0, 6).map((it, i) => (
                <div key={i} className="flex gap-2 items-start text-[11px]">
                  <SevPill sev={it.severity} />
                  <span className="text-scout-text flex-1">{it.title}</span>
                </div>
              ))}
              {items.length > 6 && <div className="font-mono text-[9.5px] text-scout-muted mt-1">+ {items.length - 6} more</div>}
            </div>
          </div>
        )
      })}
      {groups.length === 0 && (
        <div className="col-span-full py-12 text-scout-muted-2 italic font-mono text-[11px] text-center">// no findings to map yet — execute a scan to populate the surface view</div>
      )}
    </div>
  )
}