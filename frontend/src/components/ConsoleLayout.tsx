import { Shield } from 'lucide-react'

interface ConsoleLayoutProps {
  children: React.ReactNode
  activeTab: string
  onTabChange: (tab: string) => void
  scanStatus: string
  findingsCount: number
  chainsCount: number
}

const TABS = [
  { id: 'console', label: 'CONSOLE' },
  { id: 'findings', label: 'FINDINGS' },
  { id: 'chains', label: 'ATTACK CHAINS' },
  { id: 'surface', label: 'SURFACE' },
  { id: 'history', label: 'HISTORY' },
]

export default function ConsoleLayout({ children, activeTab, onTabChange, scanStatus, findingsCount, chainsCount }: ConsoleLayoutProps) {
  return (
    <div className="min-h-screen flex flex-col bg-scout-bg">
      <header className="sticky top-0 z-50 flex items-center gap-6 px-[18px] py-2.5 border-b border-scout-border bg-scout-bg/85 backdrop-blur-xl">
        <div className="flex items-center gap-2">
          <svg width="22" height="22" viewBox="0 0 22 22">
            <circle cx="11" cy="11" r="10" fill="none" stroke="var(--color-accent)" strokeWidth="1" />
            <circle cx="11" cy="11" r="6" fill="none" stroke="var(--color-accent)" strokeWidth="0.6" opacity="0.6" />
            <circle cx="11" cy="11" r="2" fill="var(--color-accent)" />
            <line x1="11" y1="0" x2="11" y2="3" stroke="var(--color-accent)" strokeWidth="1" />
            <line x1="11" y1="19" x2="11" y2="22" stroke="var(--color-accent)" strokeWidth="1" />
            <line x1="0" y1="11" x2="3" y2="11" stroke="var(--color-accent)" strokeWidth="1" />
            <line x1="19" y1="11" x2="22" y2="11" stroke="var(--color-accent)" strokeWidth="1" />
          </svg>
          <span className="font-mono font-bold text-sm tracking-[2px] text-scout-text">SCOUT</span>
          <span className="font-mono text-[10px] text-scout-muted tracking-wide">/ recon console v0.1.8</span>
        </div>

        <nav className="flex gap-0.5 flex-1">
          {TABS.map(t => (
            <button
              key={t.id}
              onClick={() => onTabChange(t.id)}
              className={`flex items-center gap-1.5 px-3 py-2 font-mono text-[10px] tracking-widest font-semibold border-b-2 transition-colors ${
                activeTab === t.id
                  ? 'text-scout-accent border-scout-accent'
                  : 'text-scout-muted border-transparent hover:text-scout-text'
              }`}
            >
              {t.label}
              {t.id === 'findings' && findingsCount > 0 && (
                <span className="bg-scout-accent/10 text-scout-accent px-1.5 py-px rounded text-[9px]">{findingsCount}</span>
              )}
              {t.id === 'chains' && chainsCount > 0 && (
                <span className="bg-scout-accent/10 text-scout-accent px-1.5 py-px rounded text-[9px]">{chainsCount}</span>
              )}
            </button>
          ))}
        </nav>

        <div className="flex items-center gap-2 font-mono text-[10px] tracking-wider">
          <span className={`w-2 h-2 rounded-full ${
            scanStatus === 'running' ? 'bg-scout-high shadow-[0_0_8px_var(--color-high)] animate-dot-pulse' :
            scanStatus === 'completed' ? 'bg-scout-low shadow-[0_0_6px_var(--color-low)]' :
            'bg-scout-muted-2'
          }`} />
          <span className="text-scout-muted">
            {scanStatus === 'running' ? 'SCANNING' : scanStatus === 'completed' ? 'COMPLETE' : 'IDLE'}
          </span>
        </div>
      </header>

      <main className="flex-1 p-4 px-[18px]">
        {children}
      </main>

      <footer className="border-t border-scout-border py-3 text-center">
        <div className="flex items-center justify-center gap-2 text-[10px] text-scout-muted font-mono">
          <Shield className="w-3 h-3 text-scout-critical" />
          AUTHORIZED TESTING ONLY — BUILT FOR RED TEAM &amp; PENTEST ENGAGEMENTS
          <Shield className="w-3 h-3 text-scout-critical" />
        </div>
      </footer>
    </div>
  )
}