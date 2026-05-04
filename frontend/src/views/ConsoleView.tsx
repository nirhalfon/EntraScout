import { useState, useEffect } from 'react'
import type { ScanData } from '../hooks/useScanEvents'
import Panel from '../components/ui/Panel'
import PhaseStrip from '../components/ui/PhaseStrip'
import LogFeed from '../components/ui/LogFeed'
import Stat from '../components/ui/Stat'
import SevBars from '../components/ui/SevBars'
import Sparkline from '../components/ui/Sparkline'

interface ConsoleViewProps {
  scanData: ScanData
  chain: any
  runId: string | null
  target: string
}

export default function ConsoleView({ scanData, chain, runId, target }: ConsoleViewProps) {
  const [qpsHistory, setQpsHistory] = useState<number[]>(Array(40).fill(0))
  const [activeSubTab, setActiveSubTab] = useState<'live' | 'report' | 'exec' | 'artifacts'>('live')
  const [, forceTick] = useState(0)

  // Tick timer for elapsed time
  useEffect(() => {
    if (scanData.status !== 'running') return
    const i = setInterval(() => forceTick(x => x + 1), 1000)
    return () => clearInterval(i)
  }, [scanData.status])

  // Simulate QPS from finding rate
  useEffect(() => {
    if (scanData.status === 'running') {
      const last = qpsHistory[qpsHistory.length - 1] || 0
      setQpsHistory(prev => [...prev.slice(1), last + Math.floor(Math.random() * 3)])
    }
  }, [scanData.findings.length])

  const sevCounts = scanData.counts
  const totalPhases = Object.keys(scanData.phases).length || 52

  return (
    <div className="flex flex-col gap-3.5">
      {/* Phase Strip */}
      {runId && <PhaseStrip phases={scanData.phases} totalPhases={totalPhases} />}

      {/* Stats row */}
      <div className="grid grid-cols-5 gap-2.5">
        <Stat label="REQUESTS" value={scanData.requests.toLocaleString()} sub="HTTP + DNS probes" />
        <Stat label="FINDINGS" value={scanData.findings.length} sub={`${(sevCounts.CRITICAL || 0) + (sevCounts.HIGH || 0)} high+`} accent={(sevCounts.CRITICAL || 0) + (sevCounts.HIGH || 0) > 0 ? 'var(--color-high)' : undefined} />
        <Stat label="CHAINS" value={chain?.nodes?.length || 0} sub="MITRE-tagged" />
        <Stat label="PHASE" value={scanData.status === 'idle' ? '—' : scanData.status === 'completed' ? 'done' : Object.values(scanData.phases).find(p => p.status === 'running')?.name || '—'} sub={scanData.status === 'running' ? `${Object.values(scanData.phases).filter(p => p.status === 'done').length}/${totalPhases}` : 'idle'} />
        <Stat label="QPS" value="" sub="">
          <Sparkline data={qpsHistory} />
        </Stat>
      </div>

      {/* Two-col: tenant + dns */}
      <div className="grid grid-cols-[1fr_1.4fr] gap-3.5 max-[1024px]:grid-cols-1">
        <Panel title="TENANT FINGERPRINT" sub={target || '—'}>
          <div className="flex flex-col gap-px">
            {target && (
              <>
                <div className="flex justify-between px-2 py-1.5 text-[11px] font-mono border-b border-dashed border-scout-border">
                  <span className="text-scout-muted tracking-wide">target</span>
                  <span className="text-scout-text text-right max-w-[60%] break-all">{target}</span>
                </div>
                {runId && (
                  <div className="flex justify-between px-2 py-1.5 text-[11px] font-mono border-b border-dashed border-scout-border">
                    <span className="text-scout-muted tracking-wide">run_id</span>
                    <span className="text-scout-text text-right max-w-[60%] break-all">{runId.slice(0, 8)}</span>
                  </div>
                )}
              </>
            )}
            {!target && <div className="text-scout-muted-2 italic p-3 text-[11px] font-mono">// no target loaded — system idle</div>}
          </div>
        </Panel>
        <Panel title="DNS / MAIL SURFACE" sub="MX · SPF · DMARC · DKIM · MTA-STS">
          <div className="flex flex-col gap-px">
            {scanData.findings.filter(f => f.phase === 'dns_surface' || f.tags?.some(t => t.startsWith('DNS'))).slice(0, 7).map((f, i) => (
              <div key={i} className="grid grid-cols-[80px_1fr_12px] gap-2.5 items-center px-2 py-1.5 text-[11px] font-mono border-b border-dashed border-scout-border last:border-b-0">
                <span className="text-scout-muted tracking-wide font-semibold">{f.tags?.[0]?.replace('DNS-', '') || f.check}</span>
                <span className="text-scout-text break-all">{f.title}</span>
                <span className={`w-1.5 h-1.5 rounded-full ${f.severity === 'HIGH' || f.severity === 'CRITICAL' ? 'bg-scout-high' : 'bg-scout-low shadow-[0_0_4px_var(--color-low)]'}`} />
              </div>
            ))}
            {scanData.findings.filter(f => f.phase === 'dns_surface').length === 0 && (
              <div className="text-scout-muted-2 italic p-3 text-[11px] font-mono">// awaiting target</div>
            )}
          </div>
        </Panel>
      </div>

      {/* Log feed */}
      <Panel title="LIVE PROBE STREAM" sub={`${scanData.logs.length} events`} dense>
        <LogFeed logs={scanData.logs} />
      </Panel>

      {/* Severity breakdown */}
      <Panel title="SEVERITY BREAKDOWN">
        <SevBars counts={sevCounts} />
      </Panel>

      {/* Sub-tabs for report/exec/artifacts */}
      {scanData.status === 'completed' && runId && (
        <>
          <div className="flex gap-1 border-b border-scout-border">
            {(['live', 'report', 'exec', 'artifacts'] as const).map(t => (
              <button key={t} onClick={() => setActiveSubTab(t)} className={`flex items-center gap-1.5 px-4 py-2.5 text-[10px] font-bold tracking-widest border-b-2 transition-colors ${activeSubTab === t ? 'border-scout-accent text-scout-accent' : 'border-transparent text-scout-muted hover:text-scout-text'}`}>
                {t.toUpperCase()}
              </button>
            ))}
          </div>
          {activeSubTab === 'report' && runId && (
            <iframe src={`/api/scans/${runId}/report.html`} className="w-full h-[70vh] rounded-sm border border-scout-border bg-scout-panel" title="Report" />
          )}
          {activeSubTab === 'exec' && runId && (
            <iframe src={`/api/scans/${runId}/executive_summary.html`} className="w-full h-[70vh] rounded-sm border border-scout-border bg-white" title="Executive Summary" />
          )}
          {activeSubTab === 'artifacts' && runId && (
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
              {['findings.json', 'issues.json', 'leads.json', 'chain.json', 'attack_paths.md', 'recommendations.md', 'tenant.json', 'run.json'].map(name => (
                <a key={name} href={`/api/scans/${runId}/artifacts/${name}`} target="_blank" rel="noreferrer" className="flex items-center gap-2 p-3 rounded-sm bg-scout-panel border border-scout-border hover:border-scout-accent/40 transition-colors text-sm font-mono">
                  {name}
                </a>
              ))}
            </div>
          )}
        </>
      )}
    </div>
  )
}