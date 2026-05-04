import { useEffect, useState } from 'react'

interface ScanRecord {
  run_id: string
  target: string
  status: string
  started_at: string
  finished_at?: string
  counts?: Record<string, number>
  error?: string
}

interface HistoryViewProps {
  onViewScan: (runId: string, target?: string) => void
}

export default function HistoryView({ onViewScan }: HistoryViewProps) {
  const [scans, setScans] = useState<ScanRecord[]>([])
  const [loading, setLoading] = useState(true)

  const fetchScans = () => {
    fetch('/api/scans')
      .then(r => r.json())
      .then(data => { setScans(data); setLoading(false) })
      .catch(() => setLoading(false))
  }

  useEffect(() => {
    fetchScans()
    const interval = setInterval(fetchScans, 5000)
    return () => clearInterval(interval)
  }, [])

  const handleRerun = (runId: string) => {
    fetch(`/api/scans/${runId}/rerun`, { method: 'POST' })
      .then(r => r.json())
      .then(data => onViewScan(data.run_id))
  }

  const handleDelete = (runId: string) => {
    if (!confirm('Delete this scan?')) return
    fetch(`/api/scans/${runId}`, { method: 'DELETE' }).then(() => fetchScans())
  }

  return (
    <div className="grid grid-cols-1 gap-3.5">
      <div className="bg-scout-panel border border-scout-border rounded-sm">
        <div className="flex items-center justify-between px-3 py-2 border-b border-scout-border bg-gradient-to-b from-scout-panel-2 to-scout-panel">
          <div className="font-mono text-[10.5px] tracking-widest font-bold text-scout-text">SCAN HISTORY</div>
          <span className="font-mono text-[10px] text-scout-muted">{scans.length} runs in this session</span>
        </div>
        <div className="p-0">
          {loading && scans.length === 0 && (
            <div className="py-6 text-scout-muted-2 italic font-mono text-[11px] text-center">LOADING SCAN ARCHIVE...</div>
          )}
          {!loading && scans.length === 0 && (
            <div className="py-6 text-scout-muted-2 italic font-mono text-[11px] text-center">// no runs yet — execute a scan from the console</div>
          )}
          {scans.length > 0 && (
            <table className="w-full border-collapse font-mono text-[11px]">
              <thead>
                <tr>
                  <th className="text-left text-scout-muted text-[9.5px] tracking-widest font-semibold px-2 py-1.5 border-b border-scout-border-2">TARGET</th>
                  <th className="text-left text-scout-muted text-[9.5px] tracking-widest font-semibold px-2 py-1.5 border-b border-scout-border-2">WHEN</th>
                  <th className="text-left text-scout-muted text-[9.5px] tracking-widest font-semibold px-2 py-1.5 border-b border-scout-border-2">FINDINGS</th>
                  <th className="text-left text-scout-muted text-[9.5px] tracking-widest font-semibold px-2 py-1.5 border-b border-scout-border-2">HIGH+</th>
                  <th className="text-left text-scout-muted text-[9.5px] tracking-widest font-semibold px-2 py-1.5 border-b border-scout-border-2"></th>
                </tr>
              </thead>
              <tbody>
                {scans.map(s => {
                  const ago = Math.floor((Date.now() - new Date(s.started_at).getTime()) / 1000)
                  const highCount = (s.counts?.CRITICAL || 0) + (s.counts?.HIGH || 0)
                  return (
                    <tr key={s.run_id} className="hover:bg-scout-accent/5">
                      <td className="px-2 py-2 text-scout-accent">{s.target}</td>
                      <td className="px-2 py-2 text-scout-muted">{ago < 60 ? `${ago}s ago` : `${Math.floor(ago / 60)}m ago`}</td>
                      <td className="px-2 py-2">{s.counts?.total || 0}</td>
                      <td className={`px-2 py-2 ${highCount > 0 ? 'text-scout-high font-semibold' : ''}`}>{highCount}</td>
                      <td className="px-2 py-2 flex gap-1">
                        <button onClick={() => onViewScan(s.run_id, s.target)} className="bg-transparent border border-scout-border-2 text-scout-muted px-2 py-0.5 text-[9.5px] tracking-wider font-semibold hover:text-scout-text hover:border-scout-muted transition-colors cursor-pointer">reload</button>
                        <button onClick={() => handleRerun(s.run_id)} className="bg-transparent border border-scout-border-2 text-scout-muted px-2 py-0.5 text-[9.5px] tracking-wider font-semibold hover:text-scout-low hover:border-scout-muted transition-colors cursor-pointer">rerun</button>
                        <button onClick={() => handleDelete(s.run_id)} className="bg-transparent border border-scout-border-2 text-scout-muted px-2 py-0.5 text-[9.5px] tracking-wider font-semibold hover:text-scout-critical hover:border-scout-muted transition-colors cursor-pointer">del</button>
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          )}
        </div>
      </div>
    </div>
  )
}