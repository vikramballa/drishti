// SVG pan/zoom with mouse wheel, drag, and two-finger pinch on touch screens.
import { useEffect, useRef, useState } from 'preact/hooks';
import type { ComponentChildren } from 'preact';

interface Props { width: number; height: number; children: ComponentChildren; focus?: { x: number; y: number } | null }

export function PanZoom({ width, height, children, focus }: Props) {
  const ref = useRef<HTMLDivElement>(null);
  const [t, setT] = useState({ x: 20, y: 20, k: 1 });
  const pointers = useRef(new Map<number, { x: number; y: number }>());
  const last = useRef<{ x: number; y: number; d: number } | null>(null);

  // Fit to width initially (but not below 0.35 — keep text legible).
  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    const k = Math.max(0.35, Math.min(1, (el.clientWidth - 40) / Math.max(1, width)));
    setT({ x: Math.max(20, (el.clientWidth - width * k) / 2), y: 20, k });
  }, [width, height]);

  useEffect(() => {
    const el = ref.current;
    if (!el || !focus) return;
    setT((o) => ({ ...o, x: el.clientWidth / 2 - focus.x * o.k, y: el.clientHeight / 3 - focus.y * o.k }));
  }, [focus?.x, focus?.y]);

  const zoomAt = (cx: number, cy: number, f: number) =>
    setT((o) => {
      const k = Math.min(3, Math.max(0.1, o.k * f));
      return { k, x: cx - ((cx - o.x) * k) / o.k, y: cy - ((cy - o.y) * k) / o.k };
    });

  return (
    <div
      ref={ref}
      class="panzoom"
      onWheel={(e) => {
        e.preventDefault();
        const r = ref.current!.getBoundingClientRect();
        if (e.ctrlKey || e.metaKey) zoomAt(e.clientX - r.left, e.clientY - r.top, Math.exp(-e.deltaY * 0.01));
        else setT((o) => ({ ...o, x: o.x - e.deltaX, y: o.y - e.deltaY }));
      }}
      onPointerDown={(e) => {
        if ((e.target as Element).closest('.node-click')) return;
        (e.currentTarget as HTMLElement).setPointerCapture(e.pointerId);
        pointers.current.set(e.pointerId, { x: e.clientX, y: e.clientY });
        last.current = null;
      }}
      onPointerMove={(e) => {
        const ps = pointers.current;
        if (!ps.has(e.pointerId)) return;
        ps.set(e.pointerId, { x: e.clientX, y: e.clientY });
        const pts = [...ps.values()];
        const r = ref.current!.getBoundingClientRect();
        const cx = pts.reduce((s, p) => s + p.x, 0) / pts.length - r.left;
        const cy = pts.reduce((s, p) => s + p.y, 0) / pts.length - r.top;
        const d = pts.length > 1 ? Math.hypot(pts[0].x - pts[1].x, pts[0].y - pts[1].y) : 0;
        const l = last.current;
        if (l) {
          setT((o) => ({ ...o, x: o.x + cx - l.x, y: o.y + cy - l.y }));
          if (d && l.d) zoomAt(cx, cy, d / l.d);
        }
        last.current = { x: cx, y: cy, d };
      }}
      onPointerUp={(e) => { pointers.current.delete(e.pointerId); last.current = null; }}
      onPointerCancel={(e) => { pointers.current.delete(e.pointerId); last.current = null; }}
    >
      <svg width="100%" height="100%">
        <g transform={`translate(${t.x},${t.y}) scale(${t.k})`}>{children}</g>
      </svg>
      <div class="zoom-ctl">
        <button aria-label="Zoom in" onClick={() => zoomAt(ref.current!.clientWidth / 2, ref.current!.clientHeight / 2, 1.25)}>+</button>
        <button aria-label="Zoom out" onClick={() => zoomAt(ref.current!.clientWidth / 2, ref.current!.clientHeight / 2, 0.8)}>−</button>
        <button aria-label="Reset view" onClick={() => setT({ x: 20, y: 20, k: Math.max(0.35, Math.min(1, (ref.current!.clientWidth - 40) / width)) })}>⟲</button>
      </div>
    </div>
  );
}
