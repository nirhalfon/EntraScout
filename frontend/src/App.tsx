import { useState, useCallback } from 'react'
import ConsoleLayout from './components/ConsoleLayout'
import CommandBar from './components/CommandBar'
import ConsoleView from './views/ConsoleView'
import FindingsView from './views/FindingsView'
import ChainsView from './views/ChainsView'
import SurfaceView from './views/SurfaceView'
import HistoryView from './views/HistoryView'
import { useScanEvents, useScanChain } from './hooks/useScanEvents'

type TabId = 'console' | 'findings' | 'chains' | 'surface' | 'history'

export default function App() {
  const [activeTab, setActiveTab] = useState<TabId>('console')
  const [currentScanId, setCurrentScanId] = useState<string | null>(null)
  const [currentTarget, setCurrentTarget] = useState('')
  const [loading, setLoading] = useState(false)

  const scanData = useScanEvents(currentScanId)
  const chain = useScanChain(currentScanId, scanData.status)

  const handleScanStart = useCallback((target: string, options: Record<string, unknown>) => {
    setLoading(true)
    setCurrentTarget(target)
    fetch('/api/scans', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(options),
    })
      .then(r => { if (!r.ok) throw new Error('Failed to start scan'); return r.json() })
      .then(data => {
        setCurrentScanId(data.run_id)
        setActiveTab('console')
        setLoading(false)
      })
      .catch(err => {
        alert(err.message)
        setLoading(false)
      })
  }, [])

  const handleCancel = useCallback(() => {
    // For now, just mark as not loading
    setLoading(false)
  }, [])

  const handleViewScan = useCallback((runId: string, target?: string) => {
    setCurrentScanId(runId)
    if (target) setCurrentTarget(target)
    setActiveTab('console')
  }, [])

  return (
    <ConsoleLayout
      activeTab={activeTab}
      onTabChange={(tab: string) => setActiveTab(tab as TabId)}
      scanStatus={scanData.status}
      findingsCount={scanData.findings.length}
      chainsCount={chain?.nodes?.length || 0}
    >
      <CommandBar onSubmit={handleScanStart} loading={loading} onCancel={handleCancel} />

      <main className="flex-1">
        {activeTab === 'console' && (
          <ConsoleView scanData={scanData} chain={chain} runId={currentScanId} target={currentTarget} />
        )}
        {activeTab === 'findings' && (
          <FindingsView findings={scanData.findings} counts={scanData.counts} />
        )}
        {activeTab === 'chains' && (
          <ChainsView chain={chain} target={currentTarget} findings={scanData.findings} />
        )}
        {activeTab === 'surface' && (
          <SurfaceView findings={scanData.findings} />
        )}
        {activeTab === 'history' && (
          <HistoryView onViewScan={handleViewScan} />
        )}
      </main>
    </ConsoleLayout>
  )
}