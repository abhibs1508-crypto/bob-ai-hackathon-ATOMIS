import { useRef, useEffect, useMemo } from 'react';
import ForceGraph3D from 'react-force-graph-3d';
import * as THREE from 'three';

const PRIORITY_COLORS = {
  critical: '#ff3b5c',
  high:     '#ff8c00',
  medium:   '#f5c518',
  low:      '#22c55e',
  default:  '#3b82f6',
};

function buildGraphData(correlations) {
  const nodes = [];
  const links = [];
  const ipMap = {};

  for (const corr of correlations) {
    const priority = corr.riskScore?.priority || 'low';
    const score    = corr.riskScore?.score || 0;

    // Correlation node
    nodes.push({
      id:       corr.id,
      label:    corr.title,
      type:     'correlation',
      priority,
      score,
      val:      Math.max(4, score / 10),
      color:    PRIORITY_COLORS[priority] || PRIORITY_COLORS.default,
      data:     corr,
    });

    // IP nodes
    const ips = corr.source_ips || corr.sourceIps || [];
    for (const ip of ips) {
      if (!ipMap[ip]) {
        ipMap[ip] = true;
        nodes.push({ id: `ip-${ip}`, label: ip, type: 'ip', val: 2, color: '#4a6380' });
      }
      links.push({ source: `ip-${ip}`, target: corr.id, color: PRIORITY_COLORS[priority] + '55' });
    }

    // Target nodes
    const targets = corr.targets || [];
    for (const tgt of targets) {
      const tgtId = `tgt-${tgt}`;
      if (!nodes.find(n => n.id === tgtId)) {
        nodes.push({ id: tgtId, label: tgt, type: 'target', val: 3, color: '#1e4d7b' });
      }
      links.push({ source: corr.id, target: tgtId, color: '#1a2d44' });
    }
  }

  return { nodes, links };
}

export default function CorrelationGraph3D({ correlations, onNodeClick }) {
  const fgRef = useRef();
  const graphData = useMemo(() => buildGraphData(correlations), [correlations]);

  useEffect(() => {
    // Auto-rotate slowly
    const fg = fgRef.current;
    if (!fg) return;
    let angle = 0;
    const interval = setInterval(() => {
      angle += 0.002;
      fg.cameraPosition({ x: 400 * Math.sin(angle), z: 400 * Math.cos(angle) });
    }, 30);
    return () => clearInterval(interval);
  }, []);

  function handleNodeClick(node) {
    if (node.type === 'correlation' && onNodeClick) {
      onNodeClick(node.data);
    }
    // Zoom to node
    const distance = 120;
    const distRatio = 1 + distance / Math.hypot(node.x, node.y, node.z);
    fgRef.current?.cameraPosition(
      { x: node.x * distRatio, y: node.y * distRatio, z: node.z * distRatio },
      node,
      800
    );
  }

  return (
    <div className="w-full h-full relative" style={{ background: 'var(--bg-primary)' }}>
      {/* Legend */}
      <div className="absolute top-4 left-4 z-10 panel p-3 space-y-2" style={{ minWidth: 160 }}>
        <p className="text-[10px] uppercase tracking-widest mb-2" style={{ color: 'var(--text-muted)' }}>Legend</p>
        {Object.entries(PRIORITY_COLORS).filter(([k]) => k !== 'default').map(([k, c]) => (
          <div key={k} className="flex items-center gap-2">
            <span className="w-2.5 h-2.5 rounded-full flex-shrink-0" style={{ background: c }} />
            <span className="text-xs capitalize" style={{ color: 'var(--text-secondary)' }}>{k}</span>
          </div>
        ))}
        <div className="flex items-center gap-2">
          <span className="w-2.5 h-2.5 rounded-full flex-shrink-0" style={{ background: '#4a6380' }} />
          <span className="text-xs" style={{ color: 'var(--text-secondary)' }}>Source IP</span>
        </div>
        <div className="flex items-center gap-2">
          <span className="w-2.5 h-2.5 rounded-full flex-shrink-0" style={{ background: '#1e4d7b' }} />
          <span className="text-xs" style={{ color: 'var(--text-secondary)' }}>Target</span>
        </div>
      </div>

      <div className="absolute top-4 right-4 z-10 panel px-3 py-2">
        <p className="text-xs" style={{ color: 'var(--text-muted)' }}>Click a node to view details</p>
      </div>

      <ForceGraph3D
        ref={fgRef}
        graphData={graphData}
        backgroundColor="transparent"
        nodeLabel={node => `<div style="background:#0d1520;border:1px solid #1a2d44;padding:6px 10px;border-radius:6px;font-family:Inter,sans-serif;font-size:12px;color:#e2eaf5">${node.label}</div>`}
        nodeColor={node => node.color}
        nodeVal={node => node.val}
        linkColor={link => link.color || '#1a2d44'}
        linkWidth={1.2}
        linkDirectionalArrowLength={4}
        linkDirectionalArrowRelPos={1}
        onNodeClick={handleNodeClick}
        nodeThreeObject={node => {
          if (node.type !== 'correlation') return null;
          const sprite = new THREE.Mesh(
            new THREE.SphereGeometry(node.val * 0.8, 16, 16),
            new THREE.MeshPhongMaterial({
              color: node.color,
              emissive: node.color,
              emissiveIntensity: 0.3,
              transparent: true,
              opacity: 0.9,
            })
          );
          return sprite;
        }}
        nodeThreeObjectExtend={false}
      />
    </div>
  );
}
