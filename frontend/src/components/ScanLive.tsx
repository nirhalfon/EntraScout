import { useEffect, useRef, useState } from 'react'
import { Activity, CheckCircle2, AlertCircle, Loader2, FileText, Download, Printer } from 'lucide-react'
import FindingCard from './FindingCard'

interface ScanLiveProps {
  runId: string
  target: string
}

interface PhaseStatus {
  name: string
  status: 'pending' | 'running' | 'done' | 'error'
  findingsCount: number
}

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

export default function ScanLive({ runId, target }: ScanLiveProps) {
  const [phases, setPhases] = useState<Record<string, PhaseStatus>>({})
  const [findings, setFindings] = useState<Finding[]>([])
  const [counts, setCounts] = useState<Record<string, number>>({})
  const [status, setStatus] = useState<'running' | 'completed' | 'failed'>('running')
  const [error, setError] = useState<string | null>(null)
  const [activeTab, setActiveTab] = useState<'live' | 'report' | 'exec' | 'artifacts'>('live')
  const scrollRef = useRef<HTMLDivElement>(null)
  const totalPhases = Object.keys(phases).length || 1
  const completedPhases = Object.values(phases).filter((p) => p.status === 'done' || p.status === 'error').length

  useEffect(() => {
    const eventSource = new EventSource(`/api/scans/${runId}/events`)
    eventSource.onmessage = (event) => {
      const data = JSON.parse(event.data)
      if (data.type === 'heartbeat') return

      if (data.type === 'phase_start') {
        setPhases((prev) => ({
          ...prev,
          [data.phase]: { name: data.phase, status: 'running', findingsCount: 0 },
        }))
      } else if (data.type === 'phase_end') {
        setPhases((prev) => ({
          ...prev,
          [data.phase]: { ...prev[data.phase], status: 'done', findingsCount: data.findings_count || 0 },
        }))
      } else if (data.type === 'phase_error') {
        setPhases((prev) => ({
          ...prev,
          [data.phase]: { ...prev[data.phase], status: 'error' },
        }))
      } else if (data.type === 'finding') {
        setFindings((prev) => [data.finding, ...prev])
        setCounts((prev) => ({
          ...prev,
          [data.finding.severity]: (prev[data.finding.severity] || 0) + 1,
          total: (prev.total || 0) + 1,
        }))
      } else if (data.type === 'scan_complete') {
        setStatus('completed')
        setCounts(data.counts || {})
        eventSource.close()
      } else if (data.type === 'scan_error') {
        setStatus('failed')
        setError(data.error)
        eventSource.close()
      }
    }
    eventSource.onerror = () => {
      // SSE will auto-reconnect; if scan is done we close above
    }
    return () => {
      eventSource.close()
    }
  }, [runId])

  useEffect(() => {
    if (scrollRef.current && activeTab === 'live') {
      scrollRef.current.scrollTop = 0
    }
  }, [findings.length, activeTab])

  const severityOrder = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']
  const severityColors: Record<string, string> = {
    CRITICAL: 'bg-scout-critical text-white',
    HIGH: 'bg-scout-high text-white',
    MEDIUM: 'bg-scout-medium text-black',
    LOW: 'bg-scout-low text-black',
    INFO: 'bg-scout-info text-white',
  }

  return (
    <div className="space-y-4">
      <div className="bg-scout-panel border border-scout-border rounded-lg p-4">
        <div className="flex items-center justify-between mb-3">
          <div className="flex items-center gap-3">
            {status === 'running' && <Loader2 className="w-5 h-5 text-scout-accent animate-spin" />}
            {status === 'completed' && <CheckCircle2 className="w-5 h-5 text-scout-low" />}
            {status === 'failed' && <AlertCircle className="w-5 h-5 text-scout-critical" />}
            <div>
              <div className="text-sm font-semibold">
                {status === 'running' && `Scanning ${target}`}
                {status === 'completed' && `Scan complete: ${target}`}
                {status === 'failed' && `Scan failed: ${target}`}
              </div>
              <div className="text-xs text-scout-muted">{runId}</div>
            </div>
          </div>
          <div className="flex items-center gap-1">
            {status === 'completed' && (
              <>
                <a
                  href={`/api/scans/${runId}/report.html`}
                  target="_blank"
                  rel="noreferrer"
                  className="flex items-center gap-1 px-3 py-1.5 rounded-md bg-scout-border hover:bg-scout-accent/20 text-xs font-medium transition-colors"
                >
                  <FileText className="w-3.5 h-3.5" /> Report
                </a>
                <a
                  href={`/api/scans/${runId}/executive_summary.html`}
                  target="_blank"
                  rel="noreferrer"
                  className="flex items-center gap-1 px-3 py-1.5 rounded-md bg-scout-border hover:bg-scout-accent/20 text-xs font-medium transition-colors"
                >
                  <Printer className="w-3.5 h-3.5" /> PDF
                </a>
              </>
            )}
          </div>
        </div>

        <div className="w-full bg-scout-bg rounded-full h-2 mb-3">
          <div
            className="bg-scout-accent h-2 rounded-full transition-all"
            style={{ width: `${Math.round((completedPhases / totalPhases) * 100)}%` }}
          />
        </div>

        <div className="flex flex-wrap gap-2">
          {severityOrder.map((s) => (
            <div key={s} className={`px-2 py-1 rounded text-xs font-bold ${severityColors[s]}`}>
              {s}: {counts[s] || 0}
            </div>
          ))}
          <div className="px-2 py-1 rounded text-xs font-bold bg-scout-border text-scout-muted">
            Total: {counts.total || 0}
          </div>
        </div>

        {error && (
          <div className="mt-3 p-3 rounded-md bg-scout-critical/10 border border-scout-critical/30 text-scout-critical text-sm">
            {error}
          </div>
        )}
      </div>

      <div className="flex items-center gap-1 border-b border-scout-border">
        {[
          { id: 'live', label: 'Live Feed', icon: Activity },
          { id: 'report', label: 'Full Report', icon: FileText },
          { id: 'exec', label: 'Executive Summary', icon: Printer },
          { id: 'artifacts', label: 'Artifacts', icon: Download },
        ].map((t) => {
          const Icon = t.icon
          const active = activeTab === t.id
          return (
            <button
              key={t.id}
              onClick={() => setActiveTab(t.id as typeof activeTab)}
              className={`flex items-center gap-1.5 px-3 py-2 text-xs font-medium border-b-2 transition-colors ${
                active
                  ? 'border-scout-accent text-scout-accent'
                  : 'border-transparent text-scout-muted hover:text-scout-text'
              }`}
            >
              <Icon className="w-3.5 h-3.5" />
              {t.label}
            </button>
          )
        })}
      </div>

      {activeTab === 'live' && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
          <div className="lg:col-span-1 space-y-2">
            <div className="text-xs font-semibold text-scout-muted uppercase tracking-wider">Phases</div>
            <div className="space-y-1 max-h-[600px] overflow-y-auto scrollbar-thin pr-1">
              {Object.entries(phases).map(([name, p]) => (
                <div
                  key={name}
                  className={`flex items-center justify-between px-2 py-1.5 rounded text-xs border ${
                    p.status === 'running'
                      ? 'border-scout-accent/30 bg-scout-accent/5'
                      : p.status === 'done'
                      ? 'border-scout-low/30 bg-scout-low/5'
                      : p.status === 'error'
                      ? 'border-scout-critical/30 bg-scout-critical/5'
                      : 'border-scout-border bg-scout-panel'
                  }`}
                >
                  <div className="flex items-center gap-2">
                    {p.status === 'running' && <Loader2 className="w-3 h-3 animate-spin text-scout-accent" />}
                    {p.status === 'done' && <CheckCircle2 className="w-3 h-3 text-scout-low" />}
                    {p.status === 'error' && <AlertCircle className="w-3 h-3 text-scout-critical" />}
                    {p.status === 'pending' && <div className="w-3 h-3 rounded-full border border-scout-muted" />}
                    <span className="capitalize">{name.replace('_', ' ')}</span>
                  </div>
                  {p.findingsCount > 0 && (
                    <span className="text-scout-muted">{p.findingsCount}</span>
                  )}
                </div>
              ))}
            </div>
          </div>

          <div ref={scrollRef} className="lg:col-span-2 space-y-2 max-h-[600px] overflow-y-auto scrollbar-thin pr-1">
            <div className="text-xs font-semibold text-scout-muted uppercase tracking-wider">Live Findings</div>
            {findings.length === 0 && (
              <div className="text-sm text-scout-muted py-8 text-center">Waiting for findings...</div>
            )}
            {findings.map((f) => (
              <FindingCard key={f.id} finding={f} />
            ))}
          </div>
        </div>
      )}

      {activeTab === 'report' && (
        <iframe
          src={`/api/scans/${runId}/report.html`}
          className="w-full h-[70vh] rounded-lg border border-scout-border bg-scout-panel"
          title="Report"
        />
      )}

      {activeTab === 'exec' && (
        <iframe
          src={`/api/scans/${runId}/executive_summary.html`}
          className="w-full h-[70vh] rounded-lg border border-scout-border bg-white"
          title="Executive Summary"
        />
      )}

      {activeTab === 'artifacts' && (
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-3">
          {[
            'findings.json',
            'issues.json',
            'leads.json',
            'chain.json',
            'attack_paths.md',
            'recommendations.md',
            'tenant.json',
            'run.json',
          ].map((name) => (
            <a
              key={name}
              href={`/api/scans/${runId}/artifacts/${name}`}
              target="_blank"
              rel="noreferrer"
              className="flex items-center gap-2 p-3 rounded-md bg-scout-panel border border-scout-border hover:border-scout-accent transition-colors text-sm"
            >
              <Download className="w-4 h-4 text-scout-accent" />
              {name}
            </a>
          ))}
        </div>
      )}
    </div>
  )
}
