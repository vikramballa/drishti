// Call-graph neighbourhood of the current function.
import { useMemo, useState } from 'preact/hooks';
import { api } from '../api';
import { useAsync } from '../components/hooks';
import { layout } from '../components/layout';
import { PanZoom } from '../components/PanZoom';
import { binary, dataVersion, goAddr, route } from '../store';

export function CallGraph() {
  const sha = route.value.sha!;
  const addr = route.value.addr ?? binary.value?.file.entry_point ?? null;
  const [depth, setDepth] = useState(1);
  const cg = useAsync(() => (addr && binary.value?.analysed ? api.callgraph(sha, addr, depth) : null), [sha, addr, depth, binary.value?.analysed, dataVersion.value]);
  const g = useMemo(() => {
    if (!cg.data) return null;
    const nodes = cg.data.nodes.map((n) => ({ id: n.addr, w: Math.min(300, Math.max(90, n.name.length * 7.2 + 20)), h: 28 }));
    const root = cg.data.nodes.find((n) => n.root)?.addr;
    return layout(nodes, cg.data.edges.map((e) => ({ from: e.from, to: e.to, kind: 'jump' })), root);
  }, [cg.data]);
  if (!addr) return <div class="empty">Select a function.</div>;
  return (
    <div class="graph-wrap">
      <div class="code-head">
        <h2>Call graph</h2>
        <div class="actions">
          <label class="muted">Depth <input type="range" min="1" max="4" value={depth} onInput={(e) => setDepth(Number((e.target as HTMLInputElement).value))} /> {depth}</label>
        </div>
      </div>
      {cg.error && <div class="empty">{cg.error}</div>}
      {g && cg.data && (
        <PanZoom width={g.width} height={g.height}>
          {g.edges.map(({ d, back }) => <path d={d} class={`gedge e-jump${back ? ' back' : ''}`} />)}
          {cg.data.nodes.map((n) => {
            const p = g.nodes.get(n.addr);
            if (!p) return null;
            return (
              <g transform={`translate(${p.x},${p.y})`} class={`gnode cg node-click${n.root ? ' entry' : ''}${n.import ? ' imp' : ''}`} onClick={() => goAddr(n.addr, 'callgraph')} onDblClick={() => goAddr(n.addr, 'code')}>
                <rect width={p.w} height={p.h} rx="14" />
                <text x={p.w / 2} y="18" text-anchor="middle">{n.name.length > 40 ? n.name.slice(0, 38) + '…' : n.name}</text>
              </g>
            );
          })}
        </PanZoom>
      )}
    </div>
  );
}
