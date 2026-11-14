// Control-flow graph of the current function.
import { useMemo, useState } from 'preact/hooks';
import { api, FunctionDetail } from '../api';
import { useAsync } from '../components/hooks';
import { layout } from '../components/layout';
import { PanZoom } from '../components/PanZoom';
import { binary, dataVersion, go, goAddr, route } from '../store';

const CH = 7.2; // monospace char width at 12px
const LH = 15;
const MAX_LINES = 40;

export function Graph() {
  const sha = route.value.sha!;
  const addr = route.value.addr ?? binary.value?.file.entry_point ?? null;
  const fn = useAsync(() => (addr && binary.value?.analysed ? api.fn(sha, addr) : null), [sha, addr, binary.value?.analysed, dataVersion.value]);
  if (!addr) return <div class="empty">Select a function.</div>;
  if (fn.error) return <div class="empty">{fn.error}</div>;
  if (!fn.data) return <div class="empty">Loading…</div>;
  return <Cfg f={fn.data} focusAddr={route.value.addr} />;
}

function Cfg({ f, focusAddr }: { f: FunctionDetail; focusAddr: string | null }) {
  const [sel, setSel] = useState<string | null>(null);
  const big = f.blocks.length > 1500;
  const g = useMemo(() => {
    const nodes = f.blocks.map((b) => {
      const lines = b.instructions.slice(0, MAX_LINES);
      const w = Math.min(560, Math.max(120, ...lines.map((i) => (i.mnemonic.length + i.operands.length + 12 + (i.comment ? Math.min(30, i.comment.length + 3) : 0)) * CH)));
      const h = (Math.min(b.instructions.length, MAX_LINES) + (b.instructions.length > MAX_LINES ? 1 : 0) + 1) * LH + 8;
      return { id: b.start, w, h };
    });
    const edges = f.blocks.flatMap((b) => b.successors.map((s) => ({ from: b.start, to: s.target, kind: s.kind })));
    return layout(nodes, edges, f.entry);
  }, [f]);
  const focus = useMemo(() => {
    if (!focusAddr) return null;
    const blk = f.blocks.find((b) => BigInt(focusAddr) >= BigInt(b.start) && BigInt(focusAddr) < BigInt(b.end));
    const p = blk && g.nodes.get(blk.start);
    return p ? { x: p.x + p.w / 2, y: p.y } : null;
  }, [g, focusAddr]);
  return (
    <div class="graph-wrap">
      <div class="code-head">
        <h2>{f.name}</h2>
        <span class="muted">{f.metrics.block_count} blocks · {f.metrics.edge_count} edges{big ? ' · large graph' : ''}</span>
        <div class="actions"><button onClick={() => go({ view: 'code', addr: sel ?? f.entry })}>Listing</button></div>
      </div>
      <PanZoom width={g.width} height={g.height} focus={focus}>
        <defs>
          {['jump', 'true', 'false', 'fallthrough', 'switch', 'indirect'].map((k) => (
            <marker id={`ar-${k}`} viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0,0L10,5L0,10z" class={`ah e-${k}`} /></marker>
          ))}
        </defs>
        {g.edges.map(({ e, d, back }) => <path d={d} class={`gedge e-${e.kind}${back ? ' back' : ''}`} marker-end={`url(#ar-${e.kind})`} />)}
        {f.blocks.map((b) => {
          const p = g.nodes.get(b.start);
          if (!p) return null;
          const lines = b.instructions.slice(0, MAX_LINES);
          return (
            <g transform={`translate(${p.x},${p.y})`} class={`gnode${b.start === f.entry ? ' entry' : ''}${sel === b.start ? ' sel' : ''}`} onClick={() => setSel(b.start)} onDblClick={() => go({ view: 'code', addr: b.start })}>
              <rect width={p.w} height={p.h} rx="4" />
              <text x="6" y={LH} class="glabel">{b.start === f.entry ? f.name : `loc_${b.start.replace(/^0x/, '')}`}</text>
              {lines.map((i, k) => (
                <text x="6" y={LH * (k + 2)} class={`gi k-${i.kind}`}>
                  <tspan class="ga">{i.addr.slice(-6)}</tspan>
                  <tspan class="gm" dx="6">{i.mnemonic}</tspan>
                  <tspan dx="6">{i.operands}</tspan>
                  {i.comment && <tspan class="gc node-click" dx="6" onClick={(ev) => { ev.stopPropagation(); if (i.targets?.[0]) goAddr(i.targets[0], 'graph'); }}>; {i.comment.slice(0, 30)}</tspan>}
                </text>
              ))}
              {b.instructions.length > MAX_LINES && <text x="6" y={LH * (MAX_LINES + 2)} class="muted">… {b.instructions.length - MAX_LINES} more</text>}
            </g>
          );
        })}
      </PanZoom>
    </div>
  );
}
