// Layered graph layout (Sugiyama-lite) for CFGs and call graphs.
// Steps: DFS back-edge removal → longest-path layering → barycentre
// ordering sweeps → x placement toward parents → bezier edges.

export interface LNode { id: string; w: number; h: number }
export interface LEdge { from: string; to: string; kind?: string }
export interface Placed { x: number; y: number; w: number; h: number }
export interface Layout { nodes: Map<string, Placed>; edges: { e: LEdge; d: string; back: boolean }[]; width: number; height: number }

const GAP_X = 36;
const GAP_Y = 56;

export function layout(nodes: LNode[], edges: LEdge[], root?: string): Layout {
  const byId = new Map(nodes.map((n) => [n.id, n]));
  const out = new Map<string, string[]>();
  for (const n of nodes) out.set(n.id, []);
  const valid = edges.filter((e) => byId.has(e.from) && byId.has(e.to));
  for (const e of valid) out.get(e.from)!.push(e.to);

  // 1. DFS: discovery order and back edges.
  const state = new Map<string, number>(); // 1 = on stack, 2 = done
  const order: string[] = [];
  const back = new Set<string>();
  const starts = root && byId.has(root) ? [root, ...nodes.map((n) => n.id)] : nodes.map((n) => n.id);
  for (const s of starts) {
    if (state.has(s)) continue;
    const stack: [string, number][] = [[s, 0]];
    state.set(s, 1);
    order.push(s);
    while (stack.length) {
      const top = stack[stack.length - 1];
      const succ = out.get(top[0])!;
      if (top[1] < succ.length) {
        const t = succ[top[1]++];
        const st = state.get(t);
        if (st === 1) back.add(top[0] + '>' + t);
        else if (!st) { state.set(t, 1); order.push(t); stack.push([t, 0]); }
      } else {
        state.set(top[0], 2);
        stack.pop();
      }
    }
  }
  const fwd = valid.filter((e) => !back.has(e.from + '>' + e.to) && e.from !== e.to);

  // 2. Longest-path layering over the DAG (Kahn order).
  const indeg = new Map<string, number>(nodes.map((n) => [n.id, 0]));
  const fout = new Map<string, string[]>(nodes.map((n) => [n.id, []]));
  const fin = new Map<string, string[]>(nodes.map((n) => [n.id, []]));
  for (const e of fwd) { indeg.set(e.to, indeg.get(e.to)! + 1); fout.get(e.from)!.push(e.to); fin.get(e.to)!.push(e.from); }
  const layer = new Map<string, number>();
  const q = order.filter((id) => indeg.get(id) === 0);
  for (const id of q) layer.set(id, 0);
  for (let i = 0; i < q.length; i++) {
    const u = q[i];
    for (const v of fout.get(u)!) {
      layer.set(v, Math.max(layer.get(v) ?? 0, layer.get(u)! + 1));
      const d = indeg.get(v)! - 1;
      indeg.set(v, d);
      if (d === 0) q.push(v);
    }
  }
  for (const n of nodes) if (!layer.has(n.id)) layer.set(n.id, 0);
  const nl = Math.max(0, ...layer.values()) + 1;
  const layers: string[][] = Array.from({ length: nl }, () => []);
  const pos = new Map<string, number>();
  for (const id of order) layers[layer.get(id)!].push(id);
  layers.forEach((l) => l.forEach((id, i) => pos.set(id, i)));

  // 3. Barycentre ordering sweeps.
  const bary = (id: string, nbrs: string[]) => (nbrs.length ? nbrs.reduce((s, x) => s + pos.get(x)!, 0) / nbrs.length : pos.get(id)!);
  for (let it = 0; it < 4; it++) {
    const down = it % 2 === 0;
    const seq = down ? layers.slice(1) : layers.slice(0, -1).reverse();
    for (const l of seq) {
      const keys = new Map(l.map((id) => [id, bary(id, down ? fin.get(id)! : fout.get(id)!)]));
      l.sort((a, b) => keys.get(a)! - keys.get(b)!);
      l.forEach((id, i) => pos.set(id, i));
    }
  }

  // 4. Coordinates.
  const placed = new Map<string, Placed>();
  let y = 0;
  let width = 0;
  for (const l of layers) {
    const lh = Math.max(0, ...l.map((id) => byId.get(id)!.h));
    let x = 0;
    for (const id of l) {
      const n = byId.get(id)!;
      // Pull toward parents' centre, but never overlap the left neighbour.
      const ps = fin.get(id)!.map((p) => placed.get(p)).filter(Boolean) as Placed[];
      const want = ps.length ? ps.reduce((s, p) => s + p.x + p.w / 2, 0) / ps.length - n.w / 2 : x;
      const nx = Math.max(x, want);
      placed.set(id, { x: nx, y, w: n.w, h: n.h });
      x = nx + n.w + GAP_X;
    }
    width = Math.max(width, x);
    y += lh + GAP_Y;
  }
  const height = y;

  // 5. Edges.
  const outIdx = new Map<string, number>();
  const res = valid.map((e) => {
    const a = placed.get(e.from)!;
    const b = placed.get(e.to)!;
    const k = outIdx.get(e.from) ?? 0;
    outIdx.set(e.from, k + 1);
    const n = out.get(e.from)!.length;
    const sx = a.x + (a.w * (k + 1)) / (n + 1);
    const sy = a.y + a.h;
    const tx = b.x + b.w / 2;
    const ty = b.y;
    const isBack = back.has(e.from + '>' + e.to) || ty <= sy;
    let d: string;
    if (isBack) {
      const rx = Math.max(a.x + a.w, b.x + b.w) + 24 + (k * 8);
      d = `M${sx},${sy} C${sx},${sy + 30} ${rx},${sy + 30} ${rx},${(sy + ty) / 2} S${tx + 20},${ty - 30} ${tx},${ty}`;
    } else {
      const my = (sy + ty) / 2;
      d = `M${sx},${sy} C${sx},${my} ${tx},${my} ${tx},${ty}`;
    }
    return { e, d, back: isBack };
  });
  return { nodes: placed, edges: res, width: width + 60, height };
}
