import { useEffect, useMemo, useRef, useState } from 'react';
import ForceGraph2D from 'react-force-graph-2d';

const NODE_COLORS = {
  username: '#818cf8',
  email: '#34d399',
  domain: '#fbbf24',
  ip: '#fb7185',
  url: '#22d3ee',
  phone: '#c084fc',
  company: '#60a5fa',
};

export default function GraphViewer({ nodes, edges, onSelect }) {
  const graphRef = useRef(null);
  const containerRef = useRef(null);
  const [size, setSize] = useState({ width: 900, height: 560 });
  const [reducedMotion, setReducedMotion] = useState(() => (
    typeof window !== 'undefined' && window.matchMedia?.('(prefers-reduced-motion: reduce)').matches === true
  ));
  const graphData = useMemo(() => ({
    nodes: nodes.map((node) => ({ ...node })),
    links: edges.map((edge) => ({
      ...edge,
      source: edge.source_node_id,
      target: edge.target_node_id,
      type: edge.relationship,
    })),
  }), [edges, nodes]);

  useEffect(() => {
    if (!containerRef.current) return undefined;
    const resize = new ResizeObserver(([entry]) => {
      setSize({
        width: Math.max(320, Math.floor(entry.contentRect.width)),
        height: Math.max(420, Math.floor(entry.contentRect.height)),
      });
    });
    resize.observe(containerRef.current);
    return () => resize.disconnect();
  }, []);

  useEffect(() => {
    const media = window.matchMedia?.('(prefers-reduced-motion: reduce)');
    if (!media) return undefined;
    const update = (event) => setReducedMotion(event.matches);
    setReducedMotion(media.matches);
    media.addEventListener?.('change', update);
    return () => media.removeEventListener?.('change', update);
  }, []);

  return (
    <div className="graph-renderer" ref={containerRef}>
      <p className="sr-only">Visual relationship graph. Use the Relationships tab for the keyboard-accessible equivalent.</p>
      <div aria-hidden="true">
        <ForceGraph2D
          graphData={graphData}
          height={size.height}
          linkColor={() => 'rgba(148, 163, 184, 0.32)'}
          linkDirectionalParticles={reducedMotion ? 0 : 1}
          linkDirectionalParticleWidth={1.5}
          nodeColor={(node) => NODE_COLORS[node.entity_type] || '#94a3b8'}
          nodeId="id"
          nodeLabel={(node) => `${humanizeForGraph(node.entity_type)}: ${node.value}`}
          nodeRelSize={6}
          onNodeClick={(node) => {
            onSelect?.(node);
            graphRef.current?.centerAt(node.x, node.y, reducedMotion ? 0 : 500);
            graphRef.current?.zoom(5, reducedMotion ? 0 : 700);
          }}
          ref={graphRef}
          cooldownTicks={reducedMotion ? 0 : undefined}
          warmupTicks={reducedMotion ? 80 : 0}
          width={size.width}
        />
      </div>
    </div>
  );
}

function humanizeForGraph(value = '') {
  return value.replace(/_/g, ' ').replace(/\b\w/g, (letter) => letter.toUpperCase());
}
