import { render } from 'preact';
import { useEffect, useRef, useState } from 'preact/hooks';
import { api, NATIVE, ResolveHit } from './api';
import { useDebounced } from './components/hooks';
import { Icon } from './components/Icon';
import { Tour } from './components/Tour';
import { binary, binaryError, currentJob, go, goAddr, isMobile, loadBinary, mode, route, setMode, toast, View } from './store';
import { Ask } from './views/Ask';
import { CallGraph } from './views/CallGraph';
import { Checks } from './views/Checks';
import { WeakSpots } from './views/WeakSpots';
import { Code } from './views/Code';
import { Details } from './views/Details';
import { Diff } from './views/Diff';
import { Functions } from './views/Functions';
import { Graph } from './views/Graph';
import { Hex } from './views/Hex';
import { Home } from './views/Home';
import { Inside } from './views/Inside';
import { Mac } from './views/Mac';
import { Notes } from './views/Notes';
import { Overview } from './views/Overview';
import { Search } from './views/Search';
import { Settings } from './views/Settings';
import { Strings, Symbols } from './views/Tables';
import './styles.css';

type NavItem = [View, string, string];
/** Plain-language pages, shown in both modes. */
const UNDERSTAND: NavItem[] = [
  ['overview', 'Summary', 'summary'], ['ask', 'Ask Drishti', 'ask'], ['checks', 'Safety checks', 'checks'], ['weakspots', 'Weak spots', 'checks'], ['details', 'Hidden details', 'details'], ['inside', 'Look inside', 'inside'],
];
/** Technical views, Expert mode only. */
const INVESTIGATE: NavItem[] = [
  ['code', 'Code', 'code'], ['graph', 'Flow graph', 'graph'], ['callgraph', 'Calls', 'calls'], ['functions', 'Functions', 'functions'],
  ['strings', 'Text inside', 'strings'], ['imports', 'Imports', 'imports'], ['exports', 'Exports', 'exports'], ['hex', 'Raw bytes', 'hex'],
  ['search', 'Search', 'search'], ['diff', 'Compare versions', 'diff'],
];
/** Views that make sense for files without machine code (PDFs, archives, …). */
const DATA_VIEWS: View[] = ['hex', 'strings', 'search'];
/** Formats with something to show under "Look inside". */
const INSIDE_FORMATS = ['apk', 'dex', 'jar', 'java-class', 'pe-dotnet', 'wasm', 'macho', 'macho-fat', 'asar'];
const CODE_VIEWS: View[] = ['code', 'graph', 'callgraph', 'functions'];

function GoTo({ inputRef }: { inputRef: { current: HTMLInputElement | null } }) {
  const [q, setQ] = useState('');
  const [hits, setHits] = useState<ResolveHit[]>([]);
  const [open, setOpen] = useState(false);
  const [idx, setIdx] = useState(0);
  const dq = useDebounced(q, 150);
  const sha = route.value.sha;
  useEffect(() => {
    if (!sha || !dq.trim()) { setHits([]); return; }
    api.resolve(sha, dq).then((r) => { setHits(r.results); setIdx(0); }, () => setHits([]));
  }, [sha, dq]);
  if (!sha) return null;
  const pick = (h: ResolveHit) => {
    setOpen(false);
    setQ('');
    inputRef.current?.blur();
    if (h.kind === 'string') go({ view: 'strings', addr: h.addr });
    else goAddr(h.addr, route.value.view === 'graph' ? 'graph' : 'code');
  };
  return (
    <div class="goto">
      <Icon name="search" size={15} class="goto-ic" />
      <input
        ref={inputRef}
        type="search"
        placeholder={isMobile.value ? 'Go to…' : 'Go to a function, address or text   g'}
        value={q}
        aria-label="Go to"
        onFocus={() => setOpen(true)}
        onBlur={() => setTimeout(() => setOpen(false), 150)}
        onInput={(e) => { setQ((e.target as HTMLInputElement).value); setOpen(true); }}
        onKeyDown={(e) => {
          if (e.key === 'ArrowDown') { setIdx((i) => Math.min(hits.length - 1, i + 1)); e.preventDefault(); }
          if (e.key === 'ArrowUp') { setIdx((i) => Math.max(0, i - 1)); e.preventDefault(); }
          if (e.key === 'Enter' && hits[idx]) pick(hits[idx]);
          if (e.key === 'Escape') (e.target as HTMLInputElement).blur();
        }}
      />
      {open && hits.length > 0 && (
        <div class="goto-pop">
          {hits.map((h, i) => (
            <a class={i === idx ? 'on' : ''} onMouseDown={(e) => { e.preventDefault(); pick(h); }}>
              <span class={`kind k-${h.kind}`}>{h.kind}</span><span class="glab">{h.label}</span><span class="mono muted">{h.addr}</span>
            </a>
          ))}
        </div>
      )}
    </div>
  );
}

function Progress() {
  const j = currentJob.value;
  if (!j) return null;
  return <div class="progress" title={`${j.phase ?? ''}`}><span class="spin" /> <span>Reading code · {j.functions.toLocaleString()}</span></div>;
}

function Body() {
  const r = route.value;
  const k = `${r.sha}-${r.addr}`;
  switch (r.view) {
    case 'ask': return <Ask />;
    case 'checks': return <Checks />;
    case 'weakspots': return <WeakSpots />;
    case 'details': return <Details />;
    case 'inside': return <Inside />;
    case 'functions': return <Functions />;
    case 'code': return <Code key={k} />;
    case 'graph': return <Graph />;
    case 'callgraph': return <CallGraph />;
    case 'hex': return <Hex />;
    case 'strings': return <Strings />;
    case 'imports': return <Symbols which="imports" />;
    case 'exports': return <Symbols which="exports" />;
    case 'notes': return <Notes />;
    case 'search': return <Search />;
    case 'diff': return <Diff />;
    case 'settings': return <Settings />;
    default: return <Overview />;
  }
}

function ModeSwitch() {
  return (
    <div class="mode" role="group" aria-label="Detail level">
      <button class={mode.value === 'simple' ? 'on' : ''} onClick={() => setMode('simple')} title="Plain-language pages only">Simple</button>
      <button class={mode.value === 'expert' ? 'on' : ''} onClick={() => setMode('expert')} title="Also show code, graphs, bytes">Expert</button>
    </div>
  );
}

function Help({ onClose }: { onClose: () => void }) {
  return (
    <div class="sheet center" onClick={onClose}>
      <div class="help" onClick={(e) => e.stopPropagation()} role="dialog" aria-label="Help">
        <h2>How to use Drishti</h2>
        <ol>
          <li><b>Open</b> a file, pick an installed app, or check your whole Mac from the home screen.</li>
          <li><b>Summary</b> gives a verdict (green, amber, red) with reasons: who made it, what it can access, who it talks to.</li>
          <li><b>Ask Drishti</b> answers questions in plain English. Tap the small numbers in an answer to see the fact it is based on.</li>
          <li><b>Safety checks</b> run free scanners (antivirus, malware patterns, capabilities) in a sandbox, and optional online checks.</li>
          <li><b>Expert mode</b> (top right) adds the code itself: instructions, readable C-like code from Ghidra, flow graphs and raw bytes.</li>
        </ol>
        <h3>Keyboard (Expert mode)</h3>
        <dl>
          <dt><kbd>g</kbd></dt><dd>Go to a function, address or text</dd>
          <dt><kbd>Space</kbd></dt><dd>Switch between Code and Flow graph</dd>
          <dt><kbd>/</kbd></dt><dd>Search bytes or text</dd>
          <dt><kbd>Esc</kbd></dt><dd>Back</dd>
          <dt><kbd>?</kbd></dt><dd>This help</dd>
        </dl>
        <h3>Use it from Claude Code</h3>
        <p class="mono small">claude mcp add drishti -- drishti mcp</p>
        <button class="primary" onClick={onClose}>Close</button>
      </div>
    </div>
  );
}

function App() {
  const r = route.value;
  const goRef = useRef<HTMLInputElement>(null);
  const [more, setMore] = useState(false);
  const [help, setHelp] = useState(false);
  useEffect(() => {
    if (r.sha) { binary.value = binary.value?.file.sha256 === r.sha ? binary.value : null; void loadBinary(r.sha); }
  }, [r.sha]);
  useEffect(() => {
    const h = (e: KeyboardEvent) => {
      const t = e.target as HTMLElement;
      if (t.tagName === 'INPUT' || t.tagName === 'TEXTAREA' || t.tagName === 'SELECT' || e.metaKey || e.ctrlKey) return;
      if (e.key === 'g' && r.sha) { e.preventDefault(); if (mode.value !== 'expert') setMode('expert'); setTimeout(() => goRef.current?.focus(), 0); }
      if (e.key === ' ' && (r.view === 'code' || r.view === 'graph')) { e.preventDefault(); go({ view: r.view === 'code' ? 'graph' : 'code' }); }
      if (e.key === '?') setHelp((x) => !x);
      if (e.key === '/' && r.sha) { e.preventDefault(); go({ view: 'search', addr: null }); }
      if (e.key === 'Escape') { if (help) setHelp(false); else if (more) setMore(false); else history.back(); }
    };
    window.addEventListener('keydown', h);
    return () => window.removeEventListener('keydown', h);
  }, [r.view, r.sha, help, more]);
  // Leaving Expert mode while on a code view: go back to the summary.
  useEffect(() => {
    if (r.sha && mode.value === 'simple' && INVESTIGATE.some(([v]) => v === r.view)) go({ view: 'overview', addr: null });
  }, [mode.value]);
  const b = binary.value;
  const t = toast.value;
  const mobile = isMobile.value;
  const inBinary = Boolean(r.sha);
  const fmt = b?.file.format ?? '';
  const native = !b || NATIVE.includes(fmt);
  const expert = mode.value === 'expert';
  const understand = UNDERSTAND.filter(([v]) => (v !== 'inside' || !b || INSIDE_FORMATS.includes(fmt)) && (v !== 'weakspots' || native));
  const investigate = expert ? INVESTIGATE.filter(([v]) => native || DATA_VIEWS.includes(v)) : [];
  const link = (v: View) => `#/b/${r.sha}/${v}${r.addr && CODE_VIEWS.includes(v) && CODE_VIEWS.includes(r.view) ? `?a=${r.addr}` : ''}`;
  const fnPanel = inBinary && !mobile && native && expert && (r.view === 'code' || r.view === 'graph' || r.view === 'callgraph');
  const nav = (items: NavItem[]) => items.map(([v, l, ic]) => <a class={r.view === v ? 'on' : ''} href={link(v)} aria-current={r.view === v ? 'page' : undefined}><Icon name={ic} size={17} /><span>{l}</span></a>);
  const mobileMain: NavItem[] = [['overview', 'Summary', 'summary'], ['ask', 'Ask', 'ask'], ['checks', 'Checks', 'checks'], ...(expert && native ? [['code', 'Code', 'code'] as NavItem] : [['details', 'Details', 'details'] as NavItem])];
  return (
    <div class={`app${mobile ? ' mobile' : ''}${expert ? ' expert' : ''}`}>
      <a class="skip" href="#main">Skip to content</a>
      <header class="top">
        <a class="logo" href="#/" aria-label="Drishti home"><span class="logo-mark" aria-hidden="true" /><span class="logo-t">Drishti</span></a>
        {inBinary && <span class="crumb" title={b?.file.file_name}><Icon name="chevron" size={14} />{b?.file.file_name ?? '…'}</span>}
        {inBinary && expert ? <GoTo inputRef={goRef} /> : <span class="grow" />}
        <Progress />
        <ModeSwitch />
        <button class="icon" onClick={() => setHelp(true)} aria-label="Help and shortcuts" title="Help"><Icon name="help" size={19} /></button>
        <a class="icon" href="#/settings" aria-label="Settings" title="Settings"><Icon name="settings" size={19} /></a>
      </header>
      <main id="main" class={`${inBinary && !mobile ? 'with-nav' : ''}`}>
        {inBinary && !mobile && (
          <nav class="sidenav" aria-label="File views">
            <div class="nav-group">{nav(understand)}</div>
            {investigate.length > 0 && <div class="nav-group"><div class="nav-h">Investigate</div>{nav(investigate)}</div>}
            <div class="nav-group"><div class="nav-h">Yours</div>{nav([['notes', 'Notes', 'notes']])}</div>
            {!expert && native && <button class="nav-expert" onClick={() => setMode('expert')}><Icon name="code" size={15} /> Show code views</button>}
          </nav>
        )}
        {fnPanel && <aside class="side"><Functions compact /></aside>}
        <section class="content">
          {binaryError.value && inBinary ? <div class="empty">{binaryError.value}</div> : inBinary ? <Body /> : r.view === 'settings' ? <Settings /> : r.view === 'mac' ? <Mac /> : <Home />}
        </section>
      </main>
      {inBinary && mobile && (
        <nav class="bottom" aria-label="File views">
          {mobileMain.map(([v, l, ic]) => <a class={r.view === v ? 'on' : ''} href={link(v)} onClick={() => setMore(false)}><Icon name={ic} size={20} />{l}</a>)}
          <a class={more ? 'on' : ''} onClick={() => setMore(!more)}><Icon name="menu" size={20} />More</a>
        </nav>
      )}
      {more && mobile && (
        <div class="sheet" onClick={() => setMore(false)}>
          <div class="sheet-body">
            {[...understand, ...investigate, ['notes', 'Notes', 'notes'] as NavItem].filter(([v]) => !mobileMain.some(([m]) => m === v)).map(([v, l, ic]) => <a href={link(v)}><Icon name={ic} size={18} />{l}</a>)}
            <a href="#/settings"><Icon name="settings" size={18} />Settings</a>
          </div>
        </div>
      )}
      {help && <Help onClose={() => setHelp(false)} />}
      <Tour />
      {t && (
        <div class={`toast ${t.kind}`} role="status">
          <span>{t.text}</span>
          {t.action && <button onClick={() => { t.action!.run(); toast.value = null; }}>{t.action.label}</button>}
          <button class="x" aria-label="Dismiss" onClick={() => (toast.value = null)}><Icon name="close" size={14} /></button>
        </div>
      )}
    </div>
  );
}

render(<App />, document.getElementById('app')!);
