// "Look inside": readable source and building blocks for apps that aren't
// plain machine code — Android/Java (JADX), .NET (ILSpy), WebAssembly
// (WABT), the JavaScript of Electron apps (app.asar), and the class list
// of Mac/iPhone apps (ipsw).
import { useEffect, useMemo, useState } from 'preact/hooks';
import { api, FileTool } from '../api';
import { Icon } from '../components/Icon';
import { useAsync, useDebounced } from '../components/hooks';
import { VirtualList } from '../components/VirtualList';
import { binary, notify, route, toolVersion } from '../store';

const SOURCE_TOOLS = ['jadx', 'ilspy', 'wabt', 'ipsw'];

function Browser({ sha, tool, title, filter: initialFilter }: { sha: string; tool: string; title: string; filter?: (p: string) => boolean }) {
  const list = useAsync(() => api.sourceList(sha, tool), [sha, tool, toolVersion.value]);
  const [q, setQ] = useState('');
  const dq = useDebounced(q, 150);
  const [path, setPath] = useState<string | null>(null);
  const file = useAsync(() => (path ? api.sourceFile(sha, tool, path) : null), [sha, tool, path]);
  const files = useMemo(() => {
    const all = (list.data?.files ?? []).filter(([p]) => !initialFilter || initialFilter(p));
    const ql = dq.toLowerCase();
    return ql ? all.filter(([p]) => p.toLowerCase().includes(ql)) : all;
  }, [list.data, dq]);
  useEffect(() => {
    // Open the most useful file first.
    if (!path && files.length) {
      const pick = files.find(([p]) => /AndroidManifest\.xml$|package\.json$|module\.wat$|objc-classes\.h$/.test(p)) ?? files[0];
      setPath(pick[0]);
    }
  }, [files.length]);
  if (list.error) return <p class="bad small">{list.error}</p>;
  return (
    <div class="browser">
      <div class="br-list">
        <div class="br-tools">
          <input type="search" placeholder={`Search ${list.data ? files.length.toLocaleString() : ''} files…`} value={q} onInput={(e) => setQ((e.target as HTMLInputElement).value)} aria-label={`Search ${title}`} />
        </div>
        <VirtualList
          count={files.length}
          rowHeight={30}
          render={(i) => {
            const [p, n] = files[i];
            const parts = p.split('/');
            return (
              <a class={`br-row${p === path ? ' on' : ''}`} onClick={() => setPath(p)} title={p}>
                <span class="br-name">{parts[parts.length - 1]}</span>
                <span class="br-dir muted">{parts.slice(0, -1).join('/')}</span>
                <span class="br-size muted">{n < 1024 ? `${n} B` : `${(n / 1024).toFixed(0)} KB`}</span>
              </a>
            );
          }}
        />
      </div>
      <div class="br-view">
        {!path && <p class="muted pad">Pick a file.</p>}
        {path && file.loading && !file.data && <div class="skeleton" style={{ margin: '12px', height: '200px' }} />}
        {file.data && (
          <>
            <div class="br-path mono small">{file.data.path}{file.data.truncated ? ' (first 2 MB)' : ''}</div>
            <pre class="codeblock src">{file.data.text}</pre>
          </>
        )}
      </div>
    </div>
  );
}

function Classes({ t }: { t: FileTool }) {
  const classes = (t.result?.data?.classes as { name: string; super: string | null; lang: string }[] | undefined) ?? [];
  const [q, setQ] = useState('');
  const dq = useDebounced(q, 150);
  const shown = useMemo(() => {
    const ql = dq.toLowerCase();
    return ql ? classes.filter((c) => c.name.toLowerCase().includes(ql) || (c.super ?? '').toLowerCase().includes(ql)) : classes;
  }, [classes, dq]);
  return (
    <div class="classes">
      <p class="muted small">Class names are written by the developers and often describe features directly (for example <span class="mono">StoryStealthModeController</span>). Try searching for words like <i>camera</i>, <i>payment</i>, <i>tracking</i> or <i>login</i>.</p>
      <input type="search" class="wide-input" placeholder={`Search ${classes.length.toLocaleString()} classes…`} value={q} onInput={(e) => setQ((e.target as HTMLInputElement).value)} aria-label="Search classes" />
      <div class="class-list">
        <VirtualList count={shown.length} rowHeight={28} render={(i) => {
          const c = shown[i];
          return <div class="class-row"><span class={`lang l-${c.lang}`}>{c.lang === 'swift' ? 'Swift' : 'ObjC'}</span><span class="mono">{c.name}</span>{c.super && <span class="muted small mono">: {c.super}</span>}</div>;
        }} />
      </div>
    </div>
  );
}

export function Inside() {
  const sha = route.value.sha!;
  const b = binary.value;
  const tools = useAsync(() => api.fileTools(sha), [sha, toolVersion.value]);
  const ins = useAsync(() => api.insights(sha), [sha]);
  const src = (tools.data?.tools ?? []).filter((t) => SOURCE_TOOLS.includes(t.id));
  const asar = b?.file.format === 'asar' || Boolean(ins.data?.bundle?.asar);
  const tabs = [...(asar ? ['asar'] : []), ...src.map((t) => t.id)];
  const [tab, setTab] = useState<string | null>(null);
  const cur = tab ?? tabs[0] ?? null;
  const t = src.find((x) => x.id === cur);
  const label: Record<string, string> = { asar: 'App JavaScript', jadx: 'Java code', ilspy: 'C# code', wabt: 'WebAssembly', ipsw: 'Classes' };
  return (
    <div class="page inside-page">
      <header class="page-head"><div><h1>Look inside</h1><p class="muted">Readable code and the building blocks of this app.</p></div></header>
      {tabs.length === 0 && tools.data && <p class="empty">Drishti has no extra view for this kind of file. The <a href="#/" onClick={(e) => { e.preventDefault(); history.back(); }}>Summary</a> and Code views still apply.</p>}
      {tabs.length > 1 && <div class="seg tabs-seg">{tabs.map((x) => <button class={x === cur ? 'on' : ''} onClick={() => setTab(x)}>{label[x] ?? x}</button>)}</div>}
      {cur === 'asar' && (
        <>
          <p class="muted small">This app is built with <b>Electron</b>: most of it is JavaScript, like a website packaged as an app. Look for <span class="mono">package.json</span> (name, version, dependencies) and the main script.</p>
          <Browser sha={sha} tool="asar" title="app files" filter={(p) => !p.includes('node_modules/') || /package\.json$/.test(p)} />
        </>
      )}
      {t && (
        t.result ? (
          t.id === 'ipsw' ? <><p class="result-head">{t.result.headline}</p><Classes t={t} /><details><summary>Raw headers</summary><Browser sha={sha} tool="ipsw" title="headers" /></details></> :
          <><p class="result-head">{t.result.headline}</p><Browser sha={sha} tool={t.id} title={label[t.id]} /></>
        ) : (
          <div class="callout">
            <p><b>{t.name}</b>: {t.what}</p>
            {!t.installed ? <p class="small">Install it with <code>{t.install}</code>, then come back.</p> :
              t.status === 'running' || t.status === 'queued' ? <p class="small"><span class="spin" /> Working… large apps can take a few minutes.</p> :
              <>
                {t.status === 'failed' && <p class="small bad">{t.error}</p>}
                <button class="primary" onClick={() => api.runTool(sha, t.id).then(() => { toolVersion.value++; }, (e: Error) => notify(e.message, 'error'))}><Icon name="play" size={15} /> Open with {t.name}</button>
              </>}
          </div>
        )
      )}
    </div>
  );
}
