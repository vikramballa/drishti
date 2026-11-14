// Virtualized function list with server-side search and sorting.
import { useEffect, useRef, useState } from 'preact/hooks';
import { api, FnRow } from '../api';
import { useAsync, useDebounced } from '../components/hooks';
import { VirtualList } from '../components/VirtualList';
import { binary, currentJob, dataVersion, goAddr, route } from '../store';

const QUERY_HELP: [string, string][] = [
  ['calls:malloc', 'calls a function or import whose name contains this'],
  ['callers:main', 'is called from this function'],
  ['str:password', 'uses a string containing this'],
  ['refs:kSecClass', 'refers to a symbol, global or string'],
  ['name:/^sub_/', 'name matches a regex (/…/ works in any text term)'],
  ['size>500', 'size, blocks, insns, calls, callers, complexity, edges with > < >= <= ='],
  ['callers=0', 'nobody calls it directly'],
  ['is:leaf', 'also thunk, noreturn, unreferenced, recursive, named, renamed'],
  ['-is:thunk', 'exclude stubs'],
];

export function Functions({ compact }: { compact?: boolean }) {
  const sha = route.value.sha!;
  const [filter, setFilter] = useState('');
  const [sort, setSort] = useState('addr');
  const [help, setHelp] = useState(false);
  const [nl, setNl] = useState('');
  const [nlInfo, setNlInfo] = useState<{ query: string; notes: string[]; hint?: string; ok: boolean } | null>(null);
  const [nlBusy, setNlBusy] = useState(false);
  const askNl = async () => {
    const question = nl.trim();
    if (!question) return;
    setNlBusy(true);
    try {
      const r = await api.nlQuery(sha, question);
      if (r.understood) {
        setFilter(r.query);
        setNlInfo({ query: r.query, notes: r.notes, ok: true });
      } else {
        setNlInfo({ query: '', notes: [], hint: r.hint, ok: false });
      }
    } catch (e) {
      setNlInfo({ query: '', notes: [], hint: (e as Error).message, ok: false });
    } finally {
      setNlBusy(false);
    }
  };
  const f = useDebounced(filter, 180);
  const list = useAsync(() => (binary.value?.analysed ? api.functions(sha, f, sort) : null), [sha, f, sort, binary.value?.analysed, dataVersion.value]);
  const job = currentJob.value;
  // Further pages are appended as the user scrolls.
  const [more, setMore] = useState<FnRow[]>([]);
  const loading = useRef(false);
  useEffect(() => setMore([]), [list.data]);
  const items = more.length ? [...(list.data?.items ?? []), ...more] : list.data?.items ?? [];
  const loadMore = () => {
    if (loading.current || !list.data || items.length >= list.data.total) return;
    loading.current = true;
    api.functions(sha, f, sort, items.length).then((p) => setMore((m) => [...m, ...p.items])).finally(() => { loading.current = false; });
  };
  const cur = route.value.addr;
  return (
    <div class={`fnlist${compact ? ' compact' : ''}`}>
      {!compact && (
        <div class="fn-nl">
          <input
            type="search"
            placeholder="Ask in plain English…  e.g. functions that run shell commands"
            value={nl}
            onInput={(e) => setNl((e.target as HTMLInputElement).value)}
            onKeyDown={(e) => { if (e.key === 'Enter') askNl(); }}
            aria-label="Ask for functions in plain English"
            spellcheck={false}
          />
          <button type="button" class="small-btn" style="margin-top:0" onClick={askNl} disabled={nlBusy}>{nlBusy ? '…' : 'Find'}</button>
        </div>
      )}
      {nlInfo && (
        <div class={`fn-nl-info small${nlInfo.ok ? '' : ' fn-err'}`}>
          {nlInfo.ok
            ? <>Understood as <code onClick={() => setFilter(nlInfo.query)}>{nlInfo.query}</code>{nlInfo.notes.length > 0 && <span class="muted"> — {nlInfo.notes.join('; ')}</span>}</>
            : <span class="muted">{nlInfo.hint ?? 'Could not translate that. Try terms like JSON, file, network, shell command, encrypt, password, complex, unused.'}</span>}
        </div>
      )}
      <div class="fn-tools">
        <input type="search" placeholder="Search functions…  e.g. calls:malloc size>200" value={filter} onInput={(e) => setFilter((e.target as HTMLInputElement).value)} aria-label="Search functions" spellcheck={false} />
        <button type="button" class={`small-btn${help ? ' on' : ''}`} style="margin-top:0" onClick={() => setHelp(!help)} aria-expanded={help} title="Query syntax">?</button>
        <select value={sort} onChange={(e) => setSort((e.target as HTMLSelectElement).value)} aria-label="Sort">
          <option value="addr">Address</option><option value="name">Name</option><option value="size">Size</option>
          <option value="blocks">Blocks</option><option value="callers">Callers</option><option value="complexity">Complexity</option>
        </select>
      </div>
      {help && (
        <div class="fn-help">
          {QUERY_HELP.map(([ex, what]) => <div><code onClick={() => setFilter(filter ? `${filter} ${ex}` : ex)}>{ex}</code> <span class="muted">{what}</span></div>)}
          <div class="muted">Combine terms with spaces (all must match); put <code>-</code> in front to exclude. Click an example to add it.</div>
        </div>
      )}
      <div class={`fn-count muted${list.error ? ' fn-err' : ''}`}>
        {list.error ? list.error : job ? `Analysing… ${job.functions.toLocaleString()} functions` : list.data ? `${list.data.total.toLocaleString()} functions${list.data.total > items.length ? ` (showing ${items.length.toLocaleString()})` : ''}` : binary.value && !binary.value.analysed ? 'Not analysed' : 'Loading…'}
      </div>
      <VirtualList
        count={items.length}
        rowHeight={compact ? 26 : 34}
        scrollToIndex={null}
        onEndReached={loadMore}
        render={(i) => {
          const r = items[i];
          return (
            <a class={`fnrow${cur === r.entry ? ' sel' : ''}${r.thunk ? ' thunk' : ''}`} href={`#/b/${sha}/code?a=${r.entry}`} onClick={(e) => { e.preventDefault(); goAddr(r.entry, route.value.view === 'graph' ? 'graph' : 'code'); }}>
              <span class="fname">{r.renamed ? '✎ ' : ''}{r.name}</span>
              {!compact && <span class="fmeta">{r.blocks} blk · {r.size} B · {r.callers}↑ {r.calls}↓</span>}
              <span class="faddr">{r.entry.replace(/^0x/, '')}</span>
            </a>
          );
        }}
      />
    </div>
  );
}
