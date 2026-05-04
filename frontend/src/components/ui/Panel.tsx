interface PanelProps {
  title: string
  sub?: string
  children: React.ReactNode
  action?: React.ReactNode
  dense?: boolean
}

export default function Panel({ title, sub, children, action, dense }: PanelProps) {
  return (
    <div className="bg-scout-panel border border-scout-border rounded-sm">
      <div className="flex items-center justify-between px-3 py-2 border-b border-scout-border bg-gradient-to-b from-scout-panel-2 to-scout-panel">
        <div className="font-mono text-[10.5px] tracking-widest font-bold text-scout-text flex items-baseline gap-2">
          {title}
          {sub && <span className="font-normal tracking-normal text-[10px] text-scout-muted">{sub}</span>}
        </div>
        {action}
      </div>
      <div className={dense ? 'p-0' : 'p-3'}>{children}</div>
    </div>
  )
}