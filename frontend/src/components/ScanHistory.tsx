import { useEffect, useState } from 'react'
import { History, Play, Trash2, ExternalLink } from 'lucide-react'

interface ScanRecord {
  run_id: string
  target: string
  status: string
  started_at: string
  finished_at?: string
  counts?: Record<string, number>
  error?: string
}

interface ScanHistoryProps {
  onViewScan: (runId: string) => void
}

export default function ScanHistory({ onViewScan }: ScanHistoryProps) {
  const [scans, setScans] = useState<ScanRecord[]>([])
  const [loading, setLoading] = useState(true)

  const fetchScans = () => {
    fetch('/api/scans')
      .then((r) => r.json())
      .then((data) => {
        setScans(data)
        setLoading(false)
      })
  }

  useEffect(() => {
    fetchScans()
    const interval = setInterval(fetchScans, 5000)
    return () => clearInterval(interval)
  }, [])

  const handleRerun = (runId: string) => {
    fetch(`/api/scans/${runId}/rerun`, { method: 'POST' })
      .then((r) => r.json())
      .then((data) => {
        onViewScan(data.run_id)
      })
  }

  const handleDelete = (runId: string) => {
    if (!confirm('Delete this scan?')) return
    fetch(`/api/scans/${runId}`, { method: 'DELETE' }).then(() => fetchScans())
  }

  const statusColors: Record<string, string> = {
    pending: 'bg-scout-medium/20 text-scout-medium',
    running: 'bg-scout-accent/20 text-scout-accent',
    completed: 'bg-scout-low/20 text-scout-low',
    failed: 'bg-scout-critical/20 text-scout-critical',
  }

  const severityOrder = ['critical', 'high', 'medium', 'low', 'info']
  const severityDot: Record<string, string> = {
    critical: 'bg-scout-critical',
    high: 'bg-scout-high',
    medium: 'bg-scout-medium',
    low: 'bg-scout-low',
    info: 'bg-scout-info',
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2 text-lg font-semibold">
          <History className="w-5 h-5 text-scout-accent" />
          Scan History
        </div>
        <button
          onClick={fetchScans}
          className="text-xs text-scout-muted hover:text-scout-accent transition-colors"
        >
          Refresh
        </button>
      </div>

      {loading && scans.length === 0 && (
        <div className="text-sm text-scout-muted py-8 text-center">Loading...</div>
      )}

      {scans.length === 0 && !loading && (
        <div className="bg-scout-panel border border-scout-border rounded-lg p-8 text-center text-scout-muted">
          No scans yet. Start one from the New Scan tab.
        </div>
      )}

      {scans.length > 0 && (
        <div className="bg-scout-panel border border-scout-border rounded-lg overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="bg-scout-bg border-b border-scout-border">
                <tr className="text-left text-xs text-scout-muted">
                  <th className="px-4 py-2">Target</th>
                  <th className="px-4 py-2">Status</th>
                  <th className="px-4 py-2">Started</th>
                  <th className="px-4 py-2">Findings</th>
                  <th className="px-4 py-2 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-scout-border">
                {scans.map((s) => (
                  <tr key={s.run_id} className="hover:bg-scout-border/20 transition-colors">
                    <td className="px-4 py-3">
                      <div className="font-medium">{s.target}</div>
                      <div className="text-xs text-scout-muted">{s.run_id}</div>
                    </td>
                    <td className="px-4 py-3">
                      <span className={`text-xs px-2 py-0.5 rounded-full font-semibold ${statusColors[s.status] || 'bg-scout-border text-scout-muted'}`}>
                        {s.status}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-scout-muted">
                      {new Date(s.started_at).toLocaleString()}
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-2">
                        {severityOrder.map((sev) => {
                          const count = s.counts?.[sev] || 0
                          if (!count) return null
                          return (
                            <span key={sev} className="flex items-center gap-1 text-xs">
                              <span className={`w-2 h-2 rounded-full ${severityDot[sev]}`} />
                              {count}
                            </span>
                          )
                        })}
                        <span className="text-xs text-scout-muted">
                          total {s.counts?.total || 0}
                        </span>
                      </div>
                    </td>
                    <td className="px-4 py-3 text-right">
                      <div className="flex items-center justify-end gap-1">
                        <button
                          onClick={() => onViewScan(s.run_id)}
                          className="p-1.5 rounded hover:bg-scout-border text-scout-muted hover:text-scout-accent transition-colors"
                          title="View"
                        >
                          <ExternalLink className="w-4 h-4" />
                        </button>
                        <button
                          onClick={() => handleRerun(s.run_id)}
                          className="p-1.5 rounded hover:bg-scout-border text-scout-muted hover:text-scout-low transition-colors"
                          title="Re-run"
                        >
                          <Play className="w-4 h-4" />
                        </button>
                        <button
                          onClick={() => handleDelete(s.run_id)}
                          className="p-1.5 rounded hover:bg-scout-border text-scout-muted hover:text-scout-critical transition-colors"
                          title="Delete"
                        >
                          <Trash2 className="w-4 h-4" />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  )
}
