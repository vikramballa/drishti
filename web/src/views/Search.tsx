// Advanced search: text (UTF-8/UTF-16), YARA-style hex, regex over bytes,
// numbers, instruction patterns, and the same query across every file.
import { useEffect, useRef, useState } from 'preact/hooks';
import { api, SearchAllResult, SearchHit, SearchMode, SearchOpts, SearchResult } from '../api';
import { binary, go, goAddr, notify, pendingSearch, route } from '../store';

const MODES: { id: SearchMode; label: string; hint: string; placeholder: string }[] = [
  { id: 'text', label: 'Text', hint: 'Words or phrases, in any letter case, as plain or wide (UTF-16) text', placeholder: 'e.g. password' },
  { id: 'hex', label: 'Hex', hint: 'Byte patterns with wildcards, jumps and alternatives (YARA syntax)', placeholder: 'e.g. 48 8b ?? [2-4] ( e8 | e9 )' },
  { id: 'regex', label: 'Regex', hint: 'Regular expression over the raw bytes', placeholder: 'e.g. https?://[\\w.-]+' },
  { id: 'number', label: 'Number', hint: 'A value stored as 16/32/64-bit integer or float', placeholder: 'e.g. 0xdeadbeef, 4096, -1, 3.14' },
  { id: 'insn', label: 'Instructions', hint: 'Patterns in the disassembly; ";" separates consecutive instructions', placeholder: 'e.g. mov edi, *; call *malloc' },
];

const HELP: Record<SearchMode, [string, string][]> = {
  text: [['password', 'finds Password, PASSWORD… in UTF-8 and UTF-16'], ['api_key', 'matches inside longer strings too']],
  hex: [['48 8b ?? 05', '?? = any byte'], ['4? 8b', 'nibble wildcard'], ['e8 [4] c3', 'skip exactly 4 bytes'], ['e8 [2-6] c3', 'skip 2 to 6 bytes'], ['( 90 | cc cc ) c3', 'either alternative'], ['ff ~00', 'any byte except 00']],
  regex: [['https?://[\\w./-]+', 'URLs'], ['[A-Za-z0-9+/]{40,}={0,2}', 'long base64 blobs'], ['\\x7fELF', 'embedded ELF header'], ['AKIA[0-9A-Z]{16}', 'AWS access key IDs']],
  number: [['0x5be0cd19', 'SHA-256 initial value'], ['0xedb88320', 'CRC-32 polynomial'], ['443', 'port numbers'], ['3.14159', 'f32 and f64']],
  insn: [['call *malloc', 'every call to malloc'], ['xor *, 0x5a', 'XOR with a constant (simple obfuscation)'], ['mov edi, *; call *', 'a call right after a mov'], ['bl *SecItemCopyMatching', 'Keychain reads on arm64']],
};

const KIND_LABEL: Record<string, string> = { 'utf-8': 'text', 'utf-16le': 'wide', 'utf-16be': 'wide BE' };
const RECENT_KEY = 'drishti.search.recent';

function loadRecent(): SearchOpts[] {
  try { return JSON.parse(localStorage.getItem(RECENT_KEY) ?? '[]') as SearchOpts[]; } catch { return []; }
}
function saveRecent(o: SearchOpts) {
  try {
    const v = [o, ...loadRecent().filter((x) => !(x.mode === o.mode && x.q === o.q))].slice(0, 12);
    localStorage.setItem(RECENT_KEY, JSON.stringify(v));
  } catch { /* storage unavailable */ }
}

function download(name: string, type: string, text: string) {
  const a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([text], { type }));
  a.download = name;
  a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 1000);
}

const csvCell = (v: unknown) => {
  const s = v === null || v === undefined ? '' : String(v);
  return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
};

/** A YARA rule that finds the same thing (not for instruction searches). */
export function yaraRule(o: SearchOpts, fileName: string, hits: SearchHit[]): string | null {
  const id = `drishti_${fileName.replace(/[^A-Za-z0-9_]/g, '_').replace(/^(\d)/, '_$1').slice(0, 48) || 'search'}`;
  const esc = (s: string) => s.replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/\n/g, '\\n').replace(/\t/g, '\\t');
  let str: string;
  if (o.mode === 'text') {
    const enc = (o.enc ?? 'utf8,utf16le').split(',');
    const mods = [enc.includes('utf8') ? 'ascii' : '', enc.some((e) => e.startsWith('utf16')) ? 'wide' : '', o.case ? '' : 'nocase'].filter(Boolean);
    str = `$s = "${esc(o.q)}" ${mods.join(' ')}`;
  } else if (o.mode === 'hex') {
    str = `$h = { ${o.q.trim()} }`;
  } else if (o.mode === 'regex') {
    str = `$r = /${o.q.replace(/\//g, '\\/')}/${o.case ? '' : ' nocase'}`;
  } else if (o.mode === 'number') {
    const kinds = [...new Set(hits.map((h) => h.bytes).filter(Boolean))].slice(0, 8);
    if (!kinds.length) return null;
    return `rule ${id}_number {\n  meta:\n    description = "Value ${esc(o.q)} (from Drishti search)"\n  strings:\n${kinds.map((b, i) => `    $n${i} = { ${b} }`).join('\n')}\n  condition:\n    any of them\n}\n`;
  } else return null;
  return `rule ${id} {\n  meta:\n    description = "Drishti ${o.mode} search: ${esc(o.q)}"\n  strings:\n    ${str}\n  condition:\n    $${str[1]}\n}\n`;
}

function Hit({ h, onOpen }: { h: SearchHit; onOpen: () => void }) {
  const where = h.va ?? (h.offset !== undefined ? `+0x${h.offset.toString(16)}` : '');
  return (
    <div class={`shit${h.va ? '' : ' nova'}`} onClick={h.va ? onOpen : undefined} title={h.va ? 'Open' : 'Not part of the loaded program (another slice or file data)'}>
      <span class="mono muted saddr">{where}</span>
      <span class="smatch mono">
        {h.lines ? h.lines.map((l, i) => <span class="sline">{i > 0 && <span class="muted"> ⏎ </span>}{l}</span>)
          : <>{h.before && <span class="muted">{h.before}</span>}<mark>{h.text}</mark>{h.after && <span class="muted">{h.after}</span>}</>}
      </span>
      <span class="smeta">
        {h.label !== 'insn' && <span class="tag">{KIND_LABEL[h.label] ?? h.label}</span>}
        {h.section && <span class="muted ssect">{h.section.replace(/^__TEXT,|^__DATA(_CONST)?,/, '')}</span>}
        {h.function && <span class="sfn" title={h.function.entry}>{h.function.name}</span>}
      </span>
    </div>
  );
}

export function Search() {
  const sha = route.value.sha!;
  const b = binary.value;
  const [mode, setMode] = useState<SearchMode>('text');
  const [query, setQuery] = useState('');
  const [matchCase, setCase] = useState(false);
  const [enc, setEnc] = useState<string[]>(['utf8', 'utf16le']);
  const [width, setWidth] = useState('');
  const [endian, setEndian] = useState('file');
  const [scope, setScope] = useState('all');
  const [insnRegex, setInsnRegex] = useState(false);
  const [everywhere, setEverywhere] = useState(false);
  const [res, setRes] = useState<SearchResult | null>(null);
  const [all, setAll] = useState<SearchAllResult | null>(null);
  const [ran, setRan] = useState<SearchOpts | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [recent, setRecent] = useState<SearchOpts[]>(loadRecent);
  const inputRef = useRef<HTMLInputElement>(null);

  const opts = (): SearchOpts => ({
    mode, q: query, case: matchCase || undefined,
    enc: mode === 'text' && enc.join(',') !== 'utf8,utf16le' ? enc.join(',') : undefined,
    width: mode === 'number' ? width || undefined : undefined,
    endian: mode === 'number' && endian !== 'file' ? endian : undefined,
    scope: mode !== 'insn' && scope !== 'all' ? scope : undefined,
    regex: mode === 'insn' && insnRegex ? true : undefined,
  });

  const run = async (o: SearchOpts = opts(), wide = everywhere) => {
    if (!o.q.trim()) { inputRef.current?.focus(); return; }
    setBusy(true); setErr(null);
    try {
      if (wide && o.mode !== 'insn') { setRes(null); setAll(await api.searchAll(o)); } else { setAll(null); setRes(await api.search(sha, o)); }
      setRan(o);
      saveRecent(o); setRecent(loadRecent());
    } catch (e) { setErr((e as Error).message); setRes(null); setAll(null); } finally { setBusy(false); }
  };

  const apply = (o: SearchOpts) => {
    setMode(o.mode); setQuery(o.q); setCase(!!o.case);
    setEnc(o.enc ? o.enc.split(',') : ['utf8', 'utf16le']);
    setWidth(o.width ?? ''); setEndian(o.endian ?? 'file'); setScope(o.scope ?? 'all'); setInsnRegex(!!o.regex);
  };

  // A search handed over from another view or from "every file".
  useEffect(() => {
    const p = pendingSearch.value;
    if (p) { pendingSearch.value = null; apply(p); setEverywhere(false); void run(p, false); }
    else inputRef.current?.focus();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [sha]);

  const more = async () => {
    if (!ran || !res) return;
    setBusy(true);
    try {
      const n = await api.search(sha, ran, res.hits.length);
      setRes({ ...res, hits: [...res.hits, ...n.hits] });
    } catch (e) { notify((e as Error).message, 'error'); } finally { setBusy(false); }
  };

  const fullHits = async () => (ran && res ? (res.total > res.hits.length ? (await api.search(sha, ran, 0, 2000)).hits : res.hits) : []);
  const fname = b?.file.file_name ?? 'file';
  const exportCsv = async () => {
    const hits = await fullHits();
    const head = ['offset', 'address', 'section', 'function', 'kind', 'match', 'bytes'];
    const rows = hits.map((h) => [h.offset, h.va, h.section, h.function?.name, h.label, h.lines ? h.lines.join(' ; ') : h.text, h.bytes].map(csvCell).join(','));
    download(`${fname}-search.csv`, 'text/csv', [head.join(','), ...rows].join('\n'));
  };
  const exportJson = async () => {
    const hits = await fullHits();
    download(`${fname}-search.json`, 'application/json', JSON.stringify({ file: fname, sha256: sha, query: ran, total: res?.total, hits }, null, 2));
  };
  const yara = ran ? yaraRule(ran, fname, res?.hits ?? []) : null;
  const copyYara = async () => {
    if (!yara) return;
    try { await navigator.clipboard.writeText(yara); notify('YARA rule copied', 'ok'); } catch { download(`${fname}.yar`, 'text/plain', yara); }
  };

  const open = (h: SearchHit) => {
    if (!h.va) return;
    if (h.function) goAddr(h.va, 'code'); else go({ view: 'hex', addr: h.va });
  };

  const sections = [...new Set((b?.sections ?? []).filter((s) => s.file_size > 0).map((s) => s.name))];
  const m = MODES.find((x) => x.id === mode)!;
  const canAll = mode !== 'insn';
  const noCode = b && !b.analysed && mode === 'insn';

  return (
    <div class="table-view search-view">
      <div class="code-head"><h2>Search</h2><span class="muted">{m.hint}</span></div>
      <form class="search-form" onSubmit={(e) => { e.preventDefault(); void run(); }}>
        <div class="seg small-seg" role="tablist" aria-label="Search type">
          {MODES.map((x) => <button type="button" role="tab" aria-selected={mode === x.id} class={mode === x.id ? 'on' : ''} onClick={() => { setMode(x.id); setErr(null); inputRef.current?.focus(); }}>{x.label}</button>)}
        </div>
        <div class="search-bar">
          <input ref={inputRef} value={query} onInput={(e) => setQuery((e.target as HTMLInputElement).value)} placeholder={m.placeholder} aria-label="Search query" spellcheck={false} autocomplete="off" class={mode === 'text' ? '' : 'mono'} />
          <button type="submit" class="primary" disabled={busy}>{busy ? 'Searching…' : 'Search'}</button>
        </div>
        <div class="search-opts">
          {mode !== 'hex' && mode !== 'number' && <label class="check-row"><input type="checkbox" checked={matchCase} onChange={(e) => setCase((e.target as HTMLInputElement).checked)} /> Match case</label>}
          {mode === 'text' && (
            <span class="seg small-seg" aria-label="Encodings">
              {[['utf8', 'UTF-8'], ['utf16le', 'UTF-16'], ['utf16be', 'UTF-16 BE']].map(([id, l]) => (
                <button type="button" class={enc.includes(id) ? 'on' : ''} title={id === 'utf16le' ? 'Wide strings (Windows, Objective-C, Java)' : undefined}
                  onClick={() => setEnc((v) => (v.includes(id) ? (v.length > 1 ? v.filter((x) => x !== id) : v) : [...v, id]))}>{l}</button>
              ))}
            </span>
          )}
          {mode === 'number' && <>
            <label>Size <select value={width} onChange={(e) => setWidth((e.target as HTMLSelectElement).value)}>
              <option value="">Any that fits</option><option value="8">8-bit</option><option value="16">16-bit</option><option value="32">32-bit</option><option value="64">64-bit</option>
            </select></label>
            <label>Byte order <select value={endian} onChange={(e) => setEndian((e.target as HTMLSelectElement).value)}>
              <option value="file">Same as file</option><option value="le">Little-endian</option><option value="be">Big-endian</option><option value="both">Both</option>
            </select></label>
          </>}
          {mode === 'insn' && <label class="check-row"><input type="checkbox" checked={insnRegex} onChange={(e) => setInsnRegex((e.target as HTMLInputElement).checked)} /> Regular expressions</label>}
          {mode !== 'insn' && !everywhere && (
            <label>In <select value={scope} onChange={(e) => setScope((e.target as HTMLSelectElement).value)} aria-label="Where to search">
              <option value="all">Whole file</option><option value="code">Code only</option><option value="data">Data only</option>
              {sections.length > 0 && <optgroup label="Section">{sections.map((s) => <option value={`section:${s}`}>{s}</option>)}</optgroup>}
            </select></label>
          )}
          {canAll && <label class="check-row" title="Search every file you have opened in Drishti"><input type="checkbox" checked={everywhere} onChange={(e) => setEverywhere((e.target as HTMLInputElement).checked)} /> All my files</label>}
        </div>
      </form>

      {err && <div class="search-err" role="alert">{err}</div>}
      {noCode && !err && <div class="search-err">Instruction search needs the code analysed first. It starts automatically when you search.</div>}

      {res && (
        <div class="search-sum">
          <span><b>{res.total.toLocaleString()}{res.capped || res.partial ? '+' : ''}</b> match{res.total === 1 ? '' : 'es'}</span>
          {res.by_kind && Object.keys(res.by_kind).length > 1 && Object.entries(res.by_kind).map(([k, n]) => <span class="tag">{KIND_LABEL[k] ?? k} {n.toLocaleString()}</span>)}
          <span class="muted">
            {res.mode === 'insn' ? `${(res.instructions_scanned ?? 0).toLocaleString()} instructions in ${(res.functions_scanned ?? 0).toLocaleString()} functions` : `${fmtBytes(res.searched_bytes ?? 0)} searched`} · {res.elapsed_ms < 1000 ? `${res.elapsed_ms} ms` : `${(res.elapsed_ms / 1000).toFixed(1)} s`}
          </span>
          {(res.capped || res.partial) && <span class="warn-txt">{res.partial ? 'Stopped early (time limit), narrow the search' : 'Too many matches; showing the first ones'}</span>}
          <span class="grow" />
          {res.total > 0 && <>
            <button type="button" class="small-btn" onClick={() => void exportCsv()}>CSV</button>
            <button type="button" class="small-btn" onClick={() => void exportJson()}>JSON</button>
            {yara && <button type="button" class="small-btn" onClick={() => void copyYara()} title="Copy a YARA rule that finds the same thing">Copy as YARA</button>}
          </>}
        </div>
      )}
      {all && (
        <div class="search-sum">
          <span><b>{all.files.length}</b> of {all.searched} file{all.searched === 1 ? '' : 's'} match</span>
          <span class="muted">{fmtBytes(all.searched_bytes)} searched · {(all.elapsed_ms / 1000).toFixed(1)} s{all.unreadable ? ` · ${all.unreadable} no longer on disk` : ''}</span>
          {all.partial && <span class="warn-txt">Stopped early (time limit)</span>}
          <span class="grow" />
          {ran && yara && <button type="button" class="small-btn" onClick={() => void copyYara()}>Copy as YARA</button>}
        </div>
      )}

      <div class="listing search-results">
        {res?.hits.map((h) => <Hit h={h} onOpen={() => open(h)} />)}
        {res && res.hits.length < Math.min(res.total, 100000) && (
          <div class="search-more"><button type="button" disabled={busy} onClick={() => void more()}>{busy ? 'Loading…' : `Show more (${(res.total - res.hits.length).toLocaleString()} left)`}</button></div>
        )}
        {res && res.total === 0 && <div class="empty">No matches. {mode === 'text' && !enc.includes('utf16le') ? 'Try adding UTF-16. ' : ''}{scope !== 'all' ? 'Try the whole file.' : ''}</div>}
        {all?.files.map((f) => (
          <div class="sfile">
            <div class="sfile-head" onClick={() => {
              if (!ran) return;
              if (f.sha256 === sha) { setEverywhere(false); void run(ran, false); return; }
              pendingSearch.value = ran; go({ sha: f.sha256, view: 'search', addr: null });
            }}>
              <b>{f.file_name}</b><span class="muted">{f.total.toLocaleString()}{f.capped ? '+' : ''} match{f.total === 1 ? '' : 'es'} · {fmtBytes(f.size)}</span>
              <span class="grow" />{f.sha256 === sha ? <span class="tag">this file</span> : <span class="muted small">Open →</span>}
            </div>
            {f.hits.map((h) => <div class="sfile-hit mono"><span class="muted">{h.va ?? `+0x${(h.offset ?? 0).toString(16)}`}</span> <mark>{h.text}</mark></div>)}
          </div>
        ))}
        {all && all.files.length === 0 && <div class="empty">None of your {all.searched} files contain this.</div>}
        {!res && !all && !busy && (
          <div class="search-help">
            <h3>Examples</h3>
            <div class="search-ex">
              {HELP[mode].map(([ex, what]) => (
                <button type="button" class="ex" onClick={() => { setQuery(ex); inputRef.current?.focus(); }}><code>{ex}</code><span class="muted">{what}</span></button>
              ))}
            </div>
            {recent.length > 0 && <>
              <h3>Recent</h3>
              <div>{recent.map((r) => <button type="button" class="chip" onClick={() => { apply(r); void run(r); }}><span class="muted">{r.mode}</span> {r.q}</button>)}</div>
            </>}
            <p class="muted small">Tip: press <kbd>/</kbd> anywhere to come back here. Click a result to jump to it. The Functions list also takes queries such as <code>calls:malloc size&gt;200</code>.</p>
          </div>
        )}
      </div>
    </div>
  );
}

function fmtBytes(n: number) {
  if (n < 1024) return `${n} B`;
  if (n < 1 << 20) return `${(n / 1024).toFixed(0)} KB`;
  if (n < 1 << 30) return `${(n / (1 << 20)).toFixed(1)} MB`;
  return `${(n / (1 << 30)).toFixed(2)} GB`;
}
