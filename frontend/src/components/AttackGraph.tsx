import { useEffect, useRef } from 'react'
import * as d3 from 'd3'

interface ChainNode {
  tag: string
  severity?: string
}

interface ChainEdge {
  source: string
  target: string
}

interface AttackGraphProps {
  chain: {
    nodes?: ChainNode[]
    edges?: ChainEdge[]
  } | null
}

export default function AttackGraph({ chain }: AttackGraphProps) {
  const svgRef = useRef<SVGSVGElement>(null)

  useEffect(() => {
    if (!chain || !svgRef.current) return
    const nodes = chain.nodes || []
    const edges = chain.edges || []
    if (nodes.length === 0) return

    const svg = d3.select(svgRef.current)
    svg.selectAll('*').remove()

    const width = svgRef.current.clientWidth || 800
    const height = 500

    svg.attr('viewBox', `0 0 ${width} ${height}`)

    const simNodes = nodes.map((n) => ({ id: n.tag, ...n })) as d3.SimulationNodeDatum[]
    const simLinks = edges.map((e) => ({ source: e.source, target: e.target })) as d3.SimulationLinkDatum<d3.SimulationNodeDatum>[]
    const simulation = d3.forceSimulation(simNodes)
      .force('link', d3.forceLink(simLinks).id((d: any) => d.id).distance(80))
      .force('charge', d3.forceManyBody().strength(-200))
      .force('center', d3.forceCenter(width / 2, height / 2))

    const g = svg.append('g')

    const zoom = d3.zoom<SVGSVGElement, unknown>()
      .scaleExtent([0.5, 3])
      .on('zoom', (event) => {
        g.attr('transform', event.transform.toString())
      })
    svg.call(zoom as any)

    const link = g.append('g')
      .selectAll('line')
      .data(edges)
      .enter()
      .append('line')
      .attr('stroke', '#30363d')
      .attr('stroke-width', 1.5)

    const node = g.append('g')
      .selectAll('g')
      .data(nodes)
      .enter()
      .append('g')
      .call(d3.drag<any, any>()
        .on('start', (event, d) => {
          if (!event.active) simulation.alphaTarget(0.3).restart()
          d.fx = d.x
          d.fy = d.y
        })
        .on('drag', (event, d) => {
          d.fx = event.x
          d.fy = event.y
        })
        .on('end', (event, d) => {
          if (!event.active) simulation.alphaTarget(0)
          d.fx = null
          d.fy = null
        }) as any)

    const colorMap: Record<string, string> = {
      CRITICAL: '#f85149',
      HIGH: '#ff7b72',
      MEDIUM: '#d29922',
      LOW: '#56d364',
      INFO: '#58a6ff',
    }

    node.append('circle')
      .attr('r', 8)
      .attr('fill', (d: any) => colorMap[d.severity || 'INFO'] || '#58a6ff')
      .attr('stroke', '#0d1117')
      .attr('stroke-width', 2)

    node.append('text')
      .text((d: any) => d.tag)
      .attr('x', 12)
      .attr('y', 4)
      .attr('font-size', '10px')
      .attr('fill', '#c9d1d9')
      .attr('font-family', 'sans-serif')

    simulation.on('tick', () => {
      link
        .attr('x1', (d: any) => d.source.x)
        .attr('y1', (d: any) => d.source.y)
        .attr('x2', (d: any) => d.target.x)
        .attr('y2', (d: any) => d.target.y)

      node.attr('transform', (d: any) => `translate(${d.x},${d.y})`)
    })

    return () => {
      simulation.stop()
    }
  }, [chain])

  if (!chain || (chain.nodes || []).length === 0) {
    return (
      <div className="bg-scout-panel border border-scout-border rounded-lg p-8 text-center text-scout-muted text-sm">
        No chain data available. Run a scan first.
      </div>
    )
  }

  return (
    <div className="bg-scout-panel border border-scout-border rounded-lg overflow-hidden">
      <svg ref={svgRef} className="w-full h-[500px]" />
    </div>
  )
}
