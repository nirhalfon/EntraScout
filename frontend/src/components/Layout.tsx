import { useState } from 'react'
import { Radar, History, Zap, Shield, Monitor, Activity } from 'lucide-react'
import DynamicGrid from './DynamicGrid'
import ParticleBackground from './ParticleBackground'

interface LayoutProps {
  children: React.ReactNode
  activeTab: string
  onTabChange: (tab: string) => void
  scanline: boolean
  onToggleScanline: () => void
}

export default function Layout({ children, activeTab, onTabChange, scanline, onToggleScanline }: LayoutProps) {
  const tabs = [
    { id: 'scan', label: 'Mission Control', icon: Zap },
    { id: 'history', label: 'Scan History', icon: History },
  ]

  return (
    <div className={`min-h-screen flex flex-col relative ${scanline ? 'scanline' : ''}`}>
      <DynamicGrid />
      <ParticleBackground />

      <header className="relative z-10 border-b border-scout-border/60 glass">
        <div className="w-full px-6 py-3 flex items-center justify-between">
          <div className="flex items-center gap-4">
            <div className="relative">
              <div className="w-9 h-9 rounded-lg bg-scout-accent/20 border border-scout-accent/40 flex items-center justify-center">
                <Radar className="w-5 h-5 text-scout-accent animate-pulse" />
              </div>
              <div className="absolute -top-0.5 -right-0.5 w-2.5 h-2.5 rounded-full bg-scout-low animate-pulse-ring" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h1 className="text-lg font-bold tracking-tight text-glow">EntraScout</h1>
                <span className="text-[10px] px-2 py-0.5 rounded-full bg-scout-accent/15 text-scout-accent font-bold border border-scout-accent/20">SOC v0.1.8</span>
              </div>
              <div className="typing-container text-xs text-scout-muted font-mono max-w-md">
                External + Internal M365 / Entra ID / Azure recon
              </div>
            </div>
          </div>

          <div className="flex items-center gap-3">
            <div className="flex items-center gap-2 mr-2">
              <Activity className="w-3 h-3 text-scout-low" />
              <span className="text-[10px] text-scout-muted font-mono">ONLINE</span>
            </div>

            <button
              onClick={onToggleScanline}
              className={`p-2 rounded-md border text-xs transition-colors ${
                scanline
                  ? 'bg-scout-accent/20 border-scout-accent text-scout-accent'
                  : 'bg-scout-panel border-scout-border text-scout-muted hover:text-scout-text'
              }`}
              title="Toggle CRT scanline effect"
            >
              <Monitor className="w-3.5 h-3.5" />
            </button>

            <div className="flex items-center gap-1">
              {tabs.map((t) => {
                const Icon = t.icon
                const isActive = activeTab === t.id
                return (
                  <button
                    key={t.id}
                    onClick={() => onTabChange(t.id)}
                    className={`flex items-center gap-2 px-4 py-2 rounded-md text-sm font-semibold transition-all ${
                      isActive
                        ? 'bg-scout-accent/15 text-scout-accent border border-scout-accent/30 shadow-[0_0_15px_rgba(0,120,212,0.15)]'
                        : 'text-scout-muted hover:text-scout-text hover:bg-scout-elevated border border-transparent'
                    }`}
                  >
                    <Icon className="w-4 h-4" />
                    {t.label}
                  </button>
                )
              })}
            </div>
          </div>
        </div>
      </header>

      <main className="flex-1 relative z-10 w-full px-6 py-6">
        {children}
      </main>

      <footer className="relative z-10 border-t border-scout-border/60 py-3 text-center">
        <div className="flex items-center justify-center gap-2 text-[10px] text-scout-muted font-mono">
          <Shield className="w-3 h-3 text-scout-critical" />
          AUTHORIZED TESTING ONLY — BUILT FOR RED TEAM &amp; PENTEST ENGAGEMENTS
          <Shield className="w-3 h-3 text-scout-critical" />
        </div>
      </footer>
    </div>
  )
}
