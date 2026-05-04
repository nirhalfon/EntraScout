import { useState, useCallback } from 'react'
import Layout from './components/Layout'
import ScanForm from './components/ScanForm'
import ScanLive from './components/ScanLive'
import ScanHistory from './components/ScanHistory'
import AttackGraph from './components/AttackGraph'
import { Network } from 'lucide-react'

export default function App() {
  const [activeTab, setActiveTab] = useState('scan')
  const [currentScanId, setCurrentScanId] = useState<string | null>(null)
  const [currentTarget, setCurrentTarget] = useState('')
  const [loading, setLoading] = useState(false)
  const [chain, setChain] = useState(null)

  const handleScanStart = useCallback((target: string, options: Record<string, unknown>) => {
    setLoading(true)
    setCurrentTarget(target)
    fetch('/api/scans', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(options),
    })
      .then((r) => {
        if (!r.ok) throw new Error('Failed to start scan')
        return r.json()
      })
      .then((data) => {
        setCurrentScanId(data.run_id)
        setActiveTab('scan')
        setLoading(false)
        // Pre-fetch chain after a delay when scan likely done
        const pollChain = () => {
          fetch(`/api/scans/${data.run_id}/chain`)
            .then((r) => r.json())
            .then((c) => {
              if (c && c.nodes) setChain(c)
            })
            .catch(() => {})
        }
        setTimeout(pollChain, 30000)
        setTimeout(pollChain, 60000)
      })
      .catch((err) => {
        alert(err.message)
        setLoading(false)
      })
  }, [])

  const handleViewScan = useCallback((runId: string) => {
    setCurrentScanId(runId)
    setActiveTab('scan')
    fetch(`/api/scans/${runId}/chain`)
      .then((r) => r.json())
      .then((c) => {
        if (c && c.nodes) setChain(c)
      })
      .catch(() => {})
    fetch(`/api/scans/${runId}`)
      .then((r) => r.json())
      .then((s) => {
        if (s.target) setCurrentTarget(s.target)
      })
      .catch(() => {})
  }, [])

  return (
    <Layout activeTab={activeTab} onTabChange={setActiveTab}>
      {activeTab === 'scan' && (
        <div className="space-y-6">
          <ScanForm onScanStart={handleScanStart} loading={loading} />
          {currentScanId && (
            <ScanLive runId={currentScanId} target={currentTarget} />
          )}
          {chain && (
            <div className="space-y-2">
              <div className="flex items-center gap-2 text-lg font-semibold">
                <Network className="w-5 h-5 text-scout-accent" />
                Attack Chain Graph
              </div>
              <AttackGraph chain={chain} />
            </div>
          )}
        </div>
      )}

      {activeTab === 'history' && (
        <ScanHistory onViewScan={handleViewScan} />
      )}
    </Layout>
  )
}
