// Strings and imports/exports tables.
import { useState } from 'preact/hooks';
import { api, Sym } from '../api';
import { useAsync, useDebounced } from '../components/hooks';
import { VirtualList } from '../components/VirtualList';
import { goAddr, route } from '../store';

export function Strings() {
  const sha = route.value.sha!;
  const [filter, setFilter] = useState('');
  const f = useDebounced(filter, 200);
  const [open, setOpen] = useState<string | null>(route.value.addr);
  const [enc, setEnc] = useState('');
  const [min, setMin] = useState(0);
  const [refs, setRefs] = useState(false);
  const list = useAsync(() => api.strings(sha, f, 0, 20000, { enc, min, refs }), [sha, f, enc, min, refs]);
  const items = list.data?.items ?? [];
  const xr = useAsync(() => (open ? api.xrefsTo(sha, open) : null), [sha, open]);
  return (
    <div class="table-view">
      <div class="fn-tools">
        <input type="search" placeholder="Filter strings…  /regex/ works too" value={filter} onInput={(e) => setFilter((e.target as HTMLInputElement).value)} aria-label="Filter strings" spellcheck={false} />
        <span class={list.error ? 'fn-err' : 'muted'}>{list.error ?? (list.data ? `${list.data.total.toLocaleString()} strings` : 'Loading…')}</span>
      </div>
      <div class="str-opts">
        <label>Kind <select value={enc} onChange={(e) => setEnc((e.target as HTMLSelectElement).value)}>
          <option value="">All</option><option value="ascii,utf8">Plain text</option><option value="utf16le">Wide (UTF-16)</option>
        </select></label>
        <label>At least <input type="number" min={0} max={999} value={min || ''} placeholder="4" onInput={(e) => setMin(Number((e.target as HTMLInputElement).value) || 0)} /> characters</label>
        <label class="check-row"><input type="checkbox" checked={refs} onChange={(e) => setRefs((e.target as HTMLInputElement).checked)} /> Used by code</label>
      </div>
      {open && (
        <div class="xref-pop">
          <b>Xrefs to {open}</b> <button onClick={() => setOpen(null)} aria-label="Close">×</button>
          {xr.data?.items.length === 0 && <div class="muted">No code references.</div>}
          {xr.data?.items.map((x) => <a onClick={() => goAddr(x.from)}>{x.from} <span class="muted">{x.function?.name ?? ''}</span></a>)}
        </div>
      )}
      <VirtualList
        count={items.length}
        rowHeight={30}
        render={(i) => {
          const s = items[i];
          return (
            <div class="trow" onClick={() => setOpen(s.addr)}>
              <span class="mono muted taddr">{s.addr.replace(/^0x/, '')}</span>
              <span class="tval mono">{s.value}</span>
              <span class="muted tx">{s.encoding === 'utf16le' ? 'u16 ' : ''}{s.xrefs.length ? `${s.xrefs.length}×` : ''}</span>
            </div>
          );
        }}
      />
    </div>
  );
}

export function Symbols({ which }: { which: 'imports' | 'exports' }) {
  const sha = route.value.sha!;
  const [filter, setFilter] = useState('');
  const f = useDebounced(filter, 200);
  const list = useAsync(() => api.table(sha, which, f), [sha, which, f]);
  const items = list.data?.items ?? [];
  const groups = new Map<string, Sym[]>();
  for (const s of items) {
    const k = which === 'imports' ? s.library ?? '(unknown library)' : s.kind;
    groups.set(k, [...(groups.get(k) ?? []), s]);
  }
  const flat: (string | Sym)[] = [];
  for (const [k, v] of groups) { flat.push(k); flat.push(...v); }
  return (
    <div class="table-view">
      <div class="fn-tools">
        <input type="search" placeholder={`Filter ${which}…`} value={filter} onInput={(e) => setFilter((e.target as HTMLInputElement).value)} aria-label={`Filter ${which}`} />
        <span class="muted">{list.data ? `${list.data.total.toLocaleString()} ${which}` : list.error ?? 'Loading…'}</span>
      </div>
      <VirtualList
        count={flat.length}
        rowHeight={28}
        render={(i) => {
          const s = flat[i];
          if (typeof s === 'string') return <div class="tgroup">{s} <span class="muted">{groups.get(s)?.length}</span></div>;
          return (
            <div class="trow" onClick={() => goAddr(s.addr)}>
              <span class="mono muted taddr">{s.addr.replace(/^0x/, '')}</span>
              <span class="tval mono" title={s.name}>{s.demangled ?? s.name}</span>
              {s.capability && <span class={`tag cap-${s.capability}`}>{s.capability}</span>}
            </div>
          );
        }}
      />
    </div>
  );
}
