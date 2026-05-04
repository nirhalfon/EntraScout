import { useState } from 'react'
import { ChevronDown, ChevronUp, AlertTriangle, Info, CheckCircle } from 'lucide-react'

interface Finding {
  id: string
  phase: string
  check: string
  title: string
  kind: string
  severity: string
  confidence: string
  description: string
  target: string
  data: Record<string, unknown>
  tags: string[]
  enables: string[]
  mitre: string[]
  recommendation: string
  evidence: unknown[]
}

const severityConfig: Record<string, { color: string; icon: typeof AlertTriangle }> = {
  CRITICAL: { color: 'text-scout-critical border-l-scout-critical', icon: AlertTriangle },
  HIGH: { color: 'text-scout-high border-l-scout-high', icon: AlertTriangle },
  MEDIUM: { color: 'text-scout-medium border-l-scout-medium', icon: Info },
  LOW: { color: 'text-scout-low border-l-scout-low', icon: CheckCircle },
  INFO: { color: 'text-scout-info border-l-scout-info', icon: Info },
}

export default function FindingCard({ finding }: { finding: Finding }) {
  const [open, setOpen] = useState(finding.severity === 'CRITICAL' || finding.severity === 'HIGH')
  const cfg = severityConfig[finding.severity] || severityConfig.INFO
  const Icon = cfg.icon

  const kindColors: Record<string, string> = {
    ISSUE: 'bg-scout-high/20 text-scout-high',
    LEAD: 'bg-purple-500/20 text-purple-400',
    DATA: 'bg-scout-accent/20 text-scout-accent',
    VALIDATION: 'bg-scout-low/20 text-scout-low',
  }

  return (
    <div className={`bg-scout-panel border border-scout-border rounded-md border-l-4 ${cfg.color} overflow-hidden`}>
      <button
        onClick={() => setOpen(!open)}
        className="w-full flex items-center gap-3 px-4 py-3 text-left hover:bg-scout-border/20 transition-colors"
      >
        <Icon className="w-4 h-4 shrink-0" />
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2">
            <span className="text-sm font-semibold truncate">{finding.title}</span>
            <span className={`text-[10px] px-1.5 py-0.5 rounded font-bold uppercase ${kindColors[finding.kind] || 'bg-scout-border text-scout-muted'}`}>
              {finding.kind}
            </span>
          </div>
          <div className="text-xs text-scout-muted">
            {finding.phase} / {finding.check}
          </div>
        </div>
        {open ? <ChevronUp className="w-4 h-4 text-scout-muted" /> : <ChevronDown className="w-4 h-4 text-scout-muted" />}
      </button>

      {open && (
        <div className="px-4 pb-4 space-y-3 text-sm">
          <p className="text-scout-text">{finding.description}</p>
          {finding.recommendation && (
            <div className="bg-scout-bg rounded-md p-3 border border-scout-border">
              <div className="text-xs font-semibold text-scout-accent mb-1">Recommendation</div>
              <div className="text-scout-muted">{finding.recommendation}</div>
            </div>
          )}
          {finding.mitre.length > 0 && (
            <div className="flex flex-wrap gap-1">
              {finding.mitre.map((m) => (
                <span key={m} className="text-[10px] bg-scout-border px-1.5 py-0.5 rounded text-scout-muted">
                  {m}
                </span>
              ))}
            </div>
          )}
          {finding.enables.length > 0 && (
            <div className="flex flex-wrap gap-1">
              {finding.enables.map((e) => (
                <span key={e} className="text-[10px] bg-scout-high/10 text-scout-high px-1.5 py-0.5 rounded">
                  {e}
                </span>
              ))}
            </div>
          )}
          {Object.keys(finding.data).length > 0 && (
            <pre className="bg-scout-bg rounded-md p-2 text-xs overflow-x-auto text-scout-muted border border-scout-border">
              {JSON.stringify(finding.data, null, 2)}
            </pre>
          )}
        </div>
      )}
    </div>
  )
}
