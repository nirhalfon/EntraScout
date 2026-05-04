import { useEffect, useRef } from 'react'
import type { LogEntry } from '../../hooks/useScanEvents'

const LEVEL_CLASS: Record<string, string> = {
  critical: 'text-scout-high font-semibold',
  high: 'text-scout-high font-semibold',
  medium: 'text-scout-medium',
  low: 'text-scout-low',
  info: 'text-scout-text',
  trace: 'text-scout-muted',
}

export default function LogFeed({ logs }: { logs: LogEntry[] }) {
  const ref = useRef<HTMLDivElement>(null)

  useEffect(() => {
    if (ref.current) ref.current.scrollTop = ref.current.scrollHeight
  }, [logs.length])

  return (
    <div ref={ref} className="h-[320px] overflow-y-auto p-2 px-3 font-mono text-[10.5px] bg-scout-log-bg scrollbar-thin">
      {logs.length === 0 && (
        <div className="text-scout-muted-2 italic p-3">// awaiting target — paste a domain and execute</div>
      )}
      {logs.map((l, i) => (
        <div key={i} className={`grid grid-cols-[70px_38px_1fr] gap-2 py-[1px] ${LEVEL_CLASS[l.lvl] || 'text-scout-text'}`}>
          <span className="text-scout-muted-2">{l.t}</span>
          <span className="text-scout-accent">[{String(l.phase).padStart(2, '0')}]</span>
          <span className="log-msg">{l.msg}</span>
        </div>
      ))}
    </div>
  )
}