interface StatProps {
  label: string
  value: string | number
  sub?: string
  accent?: string
  children?: React.ReactNode
}

export default function Stat({ label, value, sub, accent, children }: StatProps) {
  return (
    <div className="bg-scout-panel border border-scout-border p-2.5 px-3 rounded-sm">
      <div className="font-mono text-[9.5px] tracking-widest text-scout-muted mb-1">{label}</div>
      {children ? children : (
        <div className="font-mono text-[22px] font-semibold tabular-nums leading-tight" style={accent ? { color: accent } : { color: '#c9d1d9' }}>
          {value}
        </div>
      )}
      {sub && <div className="font-mono text-[9.5px] text-scout-muted mt-0.5">{sub}</div>}
    </div>
  )
}