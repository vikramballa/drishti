// Virtualized hex view over the whole file, fetched in 64 KiB chunks,
// with section colouring and a data inspector.
import { useEffect, useMemo, useRef, useState } from 'preact/hooks';
import { api } from '../api';
import { VirtualList } from '../components/VirtualList';
import { binary, goAddr, route } from '../store';

const CHUNK = 65536;
const ROW = 16;

export function Hex() {
  const sha = route.value.sha!;
  const b = binary.value;
  const size = b?.file.size ?? 0;
  const chunks = useRef(new Map<number, Uint8Array>());
  const pending = useRef(new Set<number>());
  const [, bump] = useState(0);
  const [sel, setSel] = useState<number | null>(null);
  const [jump, setJump] = useState<number | null>(null);

  useEffect(() => { chunks.current.clear(); pending.current.clear(); }, [sha]);
  // Map the route address (VA) to a file offset.
  useEffect(() => {
    const a = route.value.addr;
    if (!a) return;
    api.vaToOffset(sha, a).then((o) => { if (o !== null) { setSel(o); setJump(Math.floor(o / ROW)); } });
  }, [sha, route.value.addr]);

  const byte = (off: number): number | undefined => {
    const c = Math.floor(off / CHUNK);
    const d = chunks.current.get(c);
    if (d) return d[off - c * CHUNK];
    if (!pending.current.has(c)) {
      pending.current.add(c);
      api.bytes(sha, c * CHUNK, CHUNK).then((r) => { chunks.current.set(c, r.data); bump((x) => x + 1); }, () => pending.current.delete(c));
    }
    return undefined;
  };

  const secs = useMemo(() => (b?.sections ?? []).filter((s) => s.file_size > 0).map((s, i) => ({ ...s, i: i % 6 })), [b]);
  const secAt = (off: number) => secs.find((s) => off >= s.file_offset && off < s.file_offset + s.file_size);
  const toVa = (off: number) => { const s = secAt(off); return s ? BigInt(s.vaddr) + BigInt(off - s.file_offset) : null; };

  const rows = Math.ceil(size / ROW);
  const inspect = sel !== null ? Array.from({ length: 8 }, (_, k) => byte(sel + k)) : [];
  const dv = inspect.every((x) => x !== undefined) && inspect.length === 8 ? new DataView(new Uint8Array(inspect as number[]).buffer) : null;
  const va = sel !== null ? toVa(sel) : null;
  let str = '';
  if (sel !== null) for (let k = 0; k < 48; k++) { const c = byte(sel + k); if (c === undefined || c < 0x20 || c > 0x7e) break; str += String.fromCharCode(c); }

  return (
    <div class="hex">
      <div class="code-head">
        <h2>Hex</h2>
        <form class="actions" onSubmit={(e) => { e.preventDefault(); const v = ((e.currentTarget as HTMLFormElement).elements.namedItem('off') as HTMLInputElement).value; const o = Number(v.startsWith('0x') ? BigInt(v) : BigInt('0x' + v)); if (!Number.isNaN(o)) { setSel(o); setJump(Math.floor(o / ROW)); } }}>
          <input name="off" placeholder="file offset (hex)" aria-label="Go to offset" />
          <button>Go</button>
        </form>
      </div>
      <div class="hex-body">
        <VirtualList
          count={rows}
          rowHeight={20}
          scrollToIndex={jump}
          class="hexrows"
          render={(r) => {
            const base = r * ROW;
            const s = secAt(base);
            const cells = [];
            const ascii = [];
            for (let k = 0; k < ROW && base + k < size; k++) {
              const v = byte(base + k);
              const o = base + k;
              const cls = `hb${sel === o ? ' sel' : ''}${v === 0 ? ' z' : ''}`;
              cells.push(<span class={cls} onClick={() => setSel(o)}>{v === undefined ? '··' : v.toString(16).padStart(2, '0')}</span>);
              ascii.push(<span class={sel === o ? 'sel' : ''} onClick={() => setSel(o)}>{v === undefined ? '·' : v >= 0x20 && v < 0x7f ? String.fromCharCode(v) : '.'}</span>);
            }
            return (
              <div class={`hexrow${s ? ` sec${s.i}` : ''}`}>
                <span class="ho">{base.toString(16).padStart(8, '0')}</span>
                <span class="hcells">{cells}</span>
                <span class="hascii">{ascii}</span>
              </div>
            );
          }}
        />
        <aside class="inspector">
          <h3>Inspector</h3>
          {sel === null ? <p class="muted">Select a byte.</p> : (
            <dl>
              <dt>Offset</dt><dd class="mono">0x{sel.toString(16)}</dd>
              {va !== null && <><dt>VA</dt><dd><a class="mono" onClick={() => goAddr('0x' + va.toString(16), 'code')}>0x{va.toString(16)}</a></dd></>}
              <dt>Section</dt><dd>{secAt(sel)?.name ?? '—'}</dd>
              {dv && <>
                <dt>u8 / i8</dt><dd class="mono">{dv.getUint8(0)} / {dv.getInt8(0)}</dd>
                <dt>u16 / i16</dt><dd class="mono">{dv.getUint16(0, true)} / {dv.getInt16(0, true)}</dd>
                <dt>u32 / i32</dt><dd class="mono">{dv.getUint32(0, true)} / {dv.getInt32(0, true)}</dd>
                <dt>u64</dt><dd class="mono">0x{dv.getBigUint64(0, true).toString(16)}</dd>
                <dt>f32</dt><dd class="mono">{dv.getFloat32(0, true).toPrecision(7)}</dd>
                <dt>f64</dt><dd class="mono">{dv.getFloat64(0, true).toPrecision(10)}</dd>
              </>}
              {str && <><dt>ASCII</dt><dd class="mono">"{str}"</dd></>}
            </dl>
          )}
        </aside>
      </div>
    </div>
  );
}
