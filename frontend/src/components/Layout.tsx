import { Satellite, History, Zap, Shield } from 'lucide-react'

interface LayoutProps {
  children: React.ReactNode
  activeTab: string
  onTabChange: (tab: string) => void
}

export default function Layout({ children, activeTab, onTabChange }: LayoutProps) {
  const tabs = [
    { id: 'scan', label: 'New Scan', icon: Zap },
    { id: 'history', label: 'History', icon: History },
  ]

  return (
    <div className="min-h-screen flex flex-col">
      <header className="border-b border-scout-border bg-scout-panel sticky top-0 z-20">
        <div className="max-w-7xl mx-auto px-4 py-3 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <Satellite className="w-6 h-6 text-scout-accent" />
            <h1 className="text-lg font-bold tracking-tight">EntraScout</h1>
            <span className="text-xs px-2 py-0.5 rounded-full bg-scout-border text-scout-muted">Web v0.1.8</span>
          </div>
          <div className="flex items-center gap-1">
            {tabs.map((t) => {
              const Icon = t.icon
              const isActive = activeTab === t.id
              return (
                <button
                  key={t.id}
                  onClick={() => onTabChange(t.id)}
                  className={`flex items-center gap-2 px-3 py-1.5 rounded-md text-sm font-medium transition-colors ${
                    isActive
                      ? 'bg-scout-accent/10 text-scout-accent'
                      : 'text-scout-muted hover:text-scout-text hover:bg-scout-border/50'
                  }`}
                >
                  <Icon className="w-4 h-4" />
                  {t.label}
                </button>
              )
            })}
          </div>
        </div>
      </header>

      <main className="flex-1 max-w-7xl w-full mx-auto px-4 py-6">
        {children}
      </main>

      <footer className="border-t border-scout-border py-3 text-center text-xs text-scout-muted">
        <div className="flex items-center justify-center gap-1">
          <Shield className="w-3 h-3 text-scout-high" />
          Authorized testing only. Built for red team &amp; pentest engagements.
        </div>
      </footer>
    </div>
  )
}
