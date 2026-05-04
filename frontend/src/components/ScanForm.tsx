import { useState, useEffect } from 'react'
import { Play, ChevronDown, ChevronUp, Target, Zap, Shield, Clock, Users, Key } from 'lucide-react'

interface PhaseInfo {
  id: string
  name: string
  description: string
}

interface ScanFormProps {
  onScanStart: (target: string, options: Record<string, unknown>) => void
  loading: boolean
}

export default function ScanForm({ onScanStart, loading }: ScanFormProps) {
  const [target, setTarget] = useState('')
  const [phases, setPhases] = useState<PhaseInfo[]>([])
  const [selectedPhases, setSelectedPhases] = useState<Set<string>>(new Set())
  const [showOptions, setShowOptions] = useState(false)
  const [quick, setQuick] = useState(false)
  const [stealth, setStealth] = useState(false)
  const [internal, setInternal] = useState(false)
  const [timeout, setTimeout] = useState(8)
  const [token, setToken] = useState('')
  const [bingKey, setBingKey] = useState('')
  const [userHint, setUserHint] = useState('')

  useEffect(() => {
    fetch('/api/phases')
      .then((r) => r.json())
      .then((data) => {
        setPhases(data)
        setSelectedPhases(new Set(data.map((p: PhaseInfo) => p.id)))
      })
  }, [])

  const togglePhase = (id: string) => {
    const next = new Set(selectedPhases)
    if (next.has(id)) next.delete(id)
    else next.add(id)
    setSelectedPhases(next)
  }

  const selectAll = () => setSelectedPhases(new Set(phases.map((p) => p.id)))
  const selectNone = () => setSelectedPhases(new Set())
  const selectQuick = () => {
    const quickIds = ['1', '2', '5', '3', '4', '13', '14', '11', '12', '6', '7', '8', '9', '10']
    setSelectedPhases(new Set(quickIds))
  }

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    if (!target.trim()) return
    const options: Record<string, unknown> = {
      target: target.trim(),
      phases: Array.from(selectedPhases),
      quick,
      stealth,
      internal,
      timeout,
      workers: 32,
    }
    if (token) options.token = token
    if (bingKey) options.bing_key = bingKey
    if (userHint) options.user_hint = userHint
    onScanStart(target.trim(), options)
  }

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      <div className="bg-scout-panel border border-scout-border rounded-lg p-4 space-y-4">
        <div className="flex items-center gap-2">
          <Target className="w-5 h-5 text-scout-accent" />
          <input
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            placeholder="target.com"
            className="flex-1 bg-scout-bg border border-scout-border rounded-md px-3 py-2 text-sm focus:outline-none focus:border-scout-accent"
          />
          <button
            type="submit"
            disabled={loading || !target.trim()}
            className="flex items-center gap-2 bg-scout-accent hover:bg-scout-accent/80 disabled:opacity-50 text-white px-4 py-2 rounded-md text-sm font-semibold transition-colors"
          >
            <Play className="w-4 h-4" />
            {loading ? 'Starting...' : 'Start Scan'}
          </button>
        </div>

        <div className="flex items-center gap-2 text-xs text-scout-muted">
          <button type="button" onClick={selectAll} className="hover:text-scout-accent">Select all</button>
          <span>·</span>
          <button type="button" onClick={selectNone} className="hover:text-scout-accent">Select none</button>
          <span>·</span>
          <button type="button" onClick={selectQuick} className="hover:text-scout-accent">Quick preset</button>
          <span>·</span>
          <span>{selectedPhases.size} / {phases.length} phases</span>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2 max-h-64 overflow-y-auto scrollbar-thin pr-1">
          {phases.map((p) => (
            <label
              key={p.id}
              className={`flex items-start gap-2 p-2 rounded-md border text-xs cursor-pointer transition-colors ${
                selectedPhases.has(p.id)
                  ? 'border-scout-accent/40 bg-scout-accent/5'
                  : 'border-scout-border/50 bg-scout-bg/50 opacity-60'
              }`}
            >
              <input
                type="checkbox"
                checked={selectedPhases.has(p.id)}
                onChange={() => togglePhase(p.id)}
                className="mt-0.5 accent-scout-accent"
              />
              <div>
                <div className="font-semibold">{p.id}. {p.name}</div>
                <div className="text-scout-muted">{p.description}</div>
              </div>
            </label>
          ))}
        </div>

        <button
          type="button"
          onClick={() => setShowOptions(!showOptions)}
          className="flex items-center gap-1 text-xs text-scout-muted hover:text-scout-text"
        >
          {showOptions ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
          Advanced options
        </button>

        {showOptions && (
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 pt-2 border-t border-scout-border">
            <label className="flex items-center gap-2 text-sm">
              <input type="checkbox" checked={quick} onChange={(e) => setQuick(e.target.checked)} className="accent-scout-accent" />
              <Zap className="w-4 h-4 text-scout-medium" /> Quick mode
            </label>
            <label className="flex items-center gap-2 text-sm">
              <input type="checkbox" checked={stealth} onChange={(e) => setStealth(e.target.checked)} className="accent-scout-accent" />
              <Shield className="w-4 h-4 text-scout-low" /> Stealth mode
            </label>
            <label className="flex items-center gap-2 text-sm">
              <input type="checkbox" checked={internal} onChange={(e) => setInternal(e.target.checked)} className="accent-scout-accent" />
              Internal mode
            </label>
            <div className="flex items-center gap-2">
              <Clock className="w-4 h-4 text-scout-muted" />
              <input
                type="number"
                value={timeout}
                onChange={(e) => setTimeout(Number(e.target.value))}
                className="w-16 bg-scout-bg border border-scout-border rounded px-2 py-1 text-sm"
              />
              <span className="text-xs text-scout-muted">timeout (s)</span>
            </div>
            <div className="flex items-center gap-2">
              <Users className="w-4 h-4 text-scout-muted" />
              <input
                value={userHint}
                onChange={(e) => setUserHint(e.target.value)}
                placeholder="ceo@target.com"
                className="flex-1 bg-scout-bg border border-scout-border rounded px-2 py-1 text-sm"
              />
            </div>
            <div className="flex items-center gap-2">
              <Key className="w-4 h-4 text-scout-muted" />
              <input
                value={token}
                onChange={(e) => setToken(e.target.value)}
                placeholder="Graph token (optional)"
                className="flex-1 bg-scout-bg border border-scout-border rounded px-2 py-1 text-sm"
              />
            </div>
            <div className="flex items-center gap-2">
              <Key className="w-4 h-4 text-scout-muted" />
              <input
                value={bingKey}
                onChange={(e) => setBingKey(e.target.value)}
                placeholder="Bing API key (optional)"
                className="flex-1 bg-scout-bg border border-scout-border rounded px-2 py-1 text-sm"
              />
            </div>
          </div>
        )}
      </div>
    </form>
  )
}
