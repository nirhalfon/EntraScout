interface SparklineProps {
  data: number[]
  color?: string
}

export default function Sparkline({ data, color = 'var(--color-accent)' }: SparklineProps) {
  if (!data || data.length < 2) return <svg width="100%" height={32} />
  const W = 200, H = 32
  const max = Math.max(1, ...data)
  const points = data.map((v, i) => {
    const x = (i / (data.length - 1)) * W
    const y = H - (v / max) * (H - 4) - 2
    return `${x},${y}`
  }).join(' ')

  return (
    <svg width="100%" height={32} viewBox={`0 0 ${W} ${H}`} preserveAspectRatio="none">
      <polyline fill="none" stroke={color} strokeWidth="1.2" points={points} />
      <polyline fill={color} fillOpacity="0.12" stroke="none" points={`0,${H} ${points} ${W},${H}`} />
    </svg>
  )
}