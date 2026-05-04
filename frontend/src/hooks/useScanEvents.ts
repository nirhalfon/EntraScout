import { useState, useEffect, useRef } from 'react'

export interface PhaseStatus {
  name: string
  status: 'pending' | 'running' | 'done' | 'error'
  findingsCount: number
}

export interface Finding {
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

export interface LogEntry {
  t: string
  phase: string
  lvl: string
  msg: string
}

export interface ScanData {
  phases: Record<string, PhaseStatus>
  findings: Finding[]
  counts: Record<string, number>
  status: 'idle' | 'running' | 'completed' | 'failed'
  error: string | null
  logs: LogEntry[]
  startedAt: number | null
  requests: number
}

const EMPTY_STATE: ScanData = {
  phases: {},
  findings: [],
  counts: {},
  status: 'idle',
  error: null,
  logs: [],
  startedAt: null,
  requests: 0,
}

function ts(): string {
  const d = new Date()
  return `${String(d.getHours()).padStart(2, '0')}:${String(d.getMinutes()).padStart(2, '0')}:${String(d.getSeconds()).padStart(2, '0')}`
}

export function useScanEvents(runId: string | null): ScanData {
  const [state, setState] = useState<ScanData>(EMPTY_STATE)
  const esRef = useRef<EventSource | null>(null)

  useEffect(() => {
    if (!runId) {
      setState(EMPTY_STATE)
      return
    }

    setState({
      ...EMPTY_STATE,
      status: 'running',
      startedAt: Date.now(),
      logs: [{ t: ts(), phase: '00', lvl: 'info', msg: `scan ${runId.slice(0, 8)} starting...` }],
    })

    const es = new EventSource(`/api/scans/${runId}/events`)
    esRef.current = es

    es.onmessage = (event) => {
      const data = JSON.parse(event.data)
      if (data.type === 'heartbeat') return

      if (data.type === 'phase_start') {
        setState(prev => ({
          ...prev,
          phases: { ...prev.phases, [data.phase]: { name: data.phase, status: 'running', findingsCount: 0 } },
          logs: [...prev.logs.slice(-300), { t: ts(), phase: data.phase, lvl: 'info', msg: `→ ${data.phase} starting` }],
        }))
      } else if (data.type === 'phase_end') {
        setState(prev => ({
          ...prev,
          phases: {
            ...prev.phases,
            [data.phase]: { ...prev.phases[data.phase], status: 'done', findingsCount: data.findings_count || 0 },
          },
          requests: prev.requests + (data.findings_count || 0),
          logs: [...prev.logs.slice(-300), { t: ts(), phase: data.phase, lvl: 'info', msg: `✓ ${data.phase} complete (${data.findings_count || 0} findings)` }],
        }))
      } else if (data.type === 'phase_error') {
        setState(prev => ({
          ...prev,
          phases: { ...prev.phases, [data.phase]: { ...prev.phases[data.phase], status: 'error' } },
          logs: [...prev.logs.slice(-300), { t: ts(), phase: data.phase, lvl: 'critical', msg: `✗ ${data.phase} error: ${data.error || 'unknown'}` }],
        }))
      } else if (data.type === 'finding') {
        setState(prev => {
          const finding = data.finding as Finding
          const newCounts = { ...prev.counts }
          newCounts[finding.severity] = (newCounts[finding.severity] || 0) + 1
          newCounts.total = (newCounts.total || 0) + 1
          return {
            ...prev,
            findings: [finding, ...prev.findings],
            counts: newCounts,
            logs: [...prev.logs.slice(-300), { t: ts(), phase: finding.phase, lvl: finding.severity.toLowerCase(), msg: `${finding.title} — ${finding.tags?.[0] || finding.check}` }],
          }
        })
      } else if (data.type === 'scan_complete') {
        setState(prev => ({
          ...prev,
          counts: data.counts || prev.counts,
          status: 'completed',
          logs: [...prev.logs.slice(-300), { t: ts(), phase: '00', lvl: 'info', msg: `scan complete · ${prev.findings.length} findings` }],
        }))
        es.close()
      } else if (data.type === 'scan_error') {
        setState(prev => ({
          ...prev,
          status: 'failed',
          error: data.error || 'Unknown error',
          logs: [...prev.logs.slice(-300), { t: ts(), phase: '00', lvl: 'critical', msg: `scan failed: ${data.error || 'unknown'}` }],
        }))
        es.close()
      }
    }

    es.onerror = () => {
      // SSE will auto-reconnect
    }

    return () => {
      es.close()
      esRef.current = null
    }
  }, [runId])

  return state
}

export function useScanChain(runId: string | null, status: string) {
  const [chain, setChain] = useState<any>(null)

  useEffect(() => {
    if (!runId) { setChain(null); return }

    const fetchChain = () => {
      fetch(`/api/scans/${runId}/chain`)
        .then(r => r.json())
        .then(c => { if (c && c.nodes) setChain(c) })
        .catch(() => {})
    }

    fetchChain()

    if (status === 'running') {
      const interval = setInterval(fetchChain, 30000)
      return () => clearInterval(interval)
    }
  }, [runId, status])

  return chain
}

export function usePhases() {
  const [phases, setPhases] = useState<Array<{ id: string; name: string; description: string }>>([])

  useEffect(() => {
    fetch('/api/phases')
      .then(r => r.json())
      .then(data => setPhases(data))
      .catch(() => {})
  }, [])

  return phases
}