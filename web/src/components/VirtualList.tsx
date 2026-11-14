// Fixed-row-height virtual list: renders only visible rows, so 50 000+
// functions stay smooth on phones.
import { useEffect, useRef, useState } from 'preact/hooks';
import type { ComponentChildren } from 'preact';

interface Props {
  count: number;
  rowHeight: number;
  render: (i: number) => ComponentChildren;
  overscan?: number;
  scrollToIndex?: number | null;
  onEndReached?: () => void;
  class?: string;
}

export function VirtualList({ count, rowHeight, render, overscan = 8, scrollToIndex, onEndReached, class: cls }: Props) {
  const ref = useRef<HTMLDivElement>(null);
  const [top, setTop] = useState(0);
  const [h, setH] = useState(600);
  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    const ro = new ResizeObserver(() => setH(el.clientHeight));
    ro.observe(el);
    setH(el.clientHeight);
    return () => ro.disconnect();
  }, []);
  useEffect(() => {
    const el = ref.current;
    if (el && scrollToIndex != null && scrollToIndex >= 0) {
      const y = scrollToIndex * rowHeight;
      if (y < el.scrollTop || y > el.scrollTop + el.clientHeight - rowHeight) el.scrollTop = Math.max(0, y - el.clientHeight / 3);
    }
  }, [scrollToIndex, rowHeight]);
  const first = Math.max(0, Math.floor(top / rowHeight) - overscan);
  const last = Math.min(count, Math.ceil((top + h) / rowHeight) + overscan);
  const rows = [];
  for (let i = first; i < last; i++) {
    rows.push(<div key={i} class="vrow" style={{ top: i * rowHeight, height: rowHeight }}>{render(i)}</div>);
  }
  return (
    <div
      ref={ref}
      class={`vlist ${cls ?? ''}`}
      onScroll={(e) => {
        const el = e.currentTarget as HTMLDivElement;
        setTop(el.scrollTop);
        if (onEndReached && el.scrollTop + el.clientHeight > el.scrollHeight - rowHeight * 20) onEndReached();
      }}
    >
      <div style={{ height: count * rowHeight, position: 'relative' }}>{rows}</div>
    </div>
  );
}
