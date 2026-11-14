// Home: three clear starting points (a file, an installed app, the whole
// Mac) and recently opened files.
import { useEffect, useState } from 'preact/hooks';
import { api, fmtSize } from '../api';
import { Icon } from '../components/Icon';
import { go, notify } from '../store';

type Recent = Awaited<ReturnType<typeof api.binaries>>['binaries'];

const FORMAT_ICON: Record<string, string> = { pdf: 'file', ooxml: 'file', ole: 'file', apk: 'app', ipa: 'app', macho: 'app', 'macho-fat': 'app', pe: 'app', 'pe-dotnet': 'app', elf: 'terminal', asar: 'inside', zip: 'inside', jar: 'code', wasm: 'code' };
const FORMAT_WORD: Record<string, string> = { pdf: 'PDF', ooxml: 'Office document', ole: 'Office document', apk: 'Android app', ipa: 'iPhone app', macho: 'Mac program', 'macho-fat': 'Mac program', pe: 'Windows program', 'pe-dotnet': 'Windows .NET', elf: 'Linux program', asar: 'Electron code', zip: 'Archive', jar: 'Java', wasm: 'WebAssembly', unknown: 'File' };

function ago(iso: string): string {
  const s = (Date.now() - new Date(iso).getTime()) / 1000;
  if (!isFinite(s)) return '';
  if (s < 60) return 'just now';
  if (s < 3600) return `${Math.floor(s / 60)} min ago`;
  if (s < 86400) return `${Math.floor(s / 3600)} h ago`;
  return new Date(iso).toLocaleDateString();
}

export function Home() {
  const [recent, setRecent] = useState<Recent>([]);
  const [path, setPath] = useState('');
  const [busy, setBusy] = useState(false);
  const [drag, setDrag] = useState(false);
  const [local, setLocal] = useState(true);
  const [apps, setApps] = useState<{ name: string; path: string }[]>([]);
  const [appQ, setAppQ] = useState('');
  const [showApps, setShowApps] = useState(false);
  useEffect(() => {
    api.binaries().then((r) => setRecent(r.binaries), () => {});
    api.settings().then((s) => setLocal(Boolean(s.local_mode)), () => {});
    api.apps().then((r) => setApps(r.apps), () => {});
  }, []);

  const upload = async (f: File) => {
    setBusy(true);
    try {
      const r = await api.upload(f);
      go({ sha: r.binary_id, view: 'overview', addr: null });
    } catch (e) {
      notify((e as Error).message, 'error');
    } finally {
      setBusy(false);
    }
  };
  const open = async (p: string = path) => {
    if (!p.trim()) return;
    setBusy(true);
    try {
      const r = await api.openPath(p);
      go({ sha: r.binary_id, view: 'overview', addr: null });
    } catch (e) {
      notify((e as Error).message, 'error');
    } finally {
      setBusy(false);
    }
  };
  const filtered = apps.filter((a) => a.name.toLowerCase().includes(appQ.toLowerCase()));
  return (
    <div class="home">
      <header class="home-hero">
        <h1>What would you like to check?</h1>
        <p>Drishti tells you what a program, app or document really is, whether it looks safe, who made it and where it came from. It only reads files. Nothing you open is ever run, and nothing leaves this computer unless you turn on online checks.</p>
      </header>

      <div class="choices">
        <label
          class={`choice drop${drag ? ' over' : ''}${busy ? ' busy' : ''}`}
          onDragOver={(e) => { e.preventDefault(); setDrag(true); }}
          onDragLeave={() => setDrag(false)}
          onDrop={(e) => { e.preventDefault(); setDrag(false); const f = e.dataTransfer?.files[0]; if (f) void upload(f); }}
        >
          <input type="file" hidden onChange={(e) => { const f = (e.target as HTMLInputElement).files?.[0]; if (f) void upload(f); }} />
          <span class="choice-ic"><Icon name="upload" size={24} /></span>
          <b>{busy ? 'Opening…' : 'Check a file'}</b>
          <span>Drop it here or click to choose. Programs, apps, PDFs, Office files, photos, archives.</span>
        </label>
        {local && apps.length > 0 && (
          <button class={`choice${showApps ? ' on' : ''}`} onClick={() => setShowApps(!showApps)} aria-expanded={showApps}>
            <span class="choice-ic"><Icon name="app" size={24} /></span>
            <b>Check an installed app</b>
            <span>Pick from the {apps.length} apps on this Mac.</span>
          </button>
        )}
        {local && (
          <a class="choice" href="#/mac">
            <span class="choice-ic"><Icon name="mac" size={24} /></span>
            <b>Check my whole Mac</b>
            <span>What starts automatically, and who made each app.</span>
          </a>
        )}
      </div>

      {showApps && (
        <section class="panel apps-panel">
          <input type="search" class="wide-input" autoFocus placeholder={`Search ${apps.length} apps…`} value={appQ} onInput={(e) => setAppQ((e.target as HTMLInputElement).value)} aria-label="Search apps" />
          <div class="apps">
            {filtered.slice(0, appQ ? 80 : 40).map((a) => (
              <button class="appbtn" disabled={busy} onClick={() => void open(a.path)} title={a.path}><span class="app-letter">{a.name.slice(0, 1)}</span><span class="app-name">{a.name}</span></button>
            ))}
          </div>
          {filtered.length === 0 && <p class="muted small">No app matches “{appQ}”.</p>}
        </section>
      )}

      {local && (
        <form class="openpath" onSubmit={(e) => { e.preventDefault(); void open(); }}>
          <input placeholder="Or type a path: ~/Downloads/invoice.pdf" value={path} onInput={(e) => setPath((e.target as HTMLInputElement).value)} aria-label="Path of a file on this computer" />
          <button type="submit" disabled={busy || !path.trim()}>Open</button>
          <p class="muted small">Opening by path also shows which website or app a download came from.</p>
        </form>
      )}

      {recent.length > 0 && (
        <section class="recent">
          <h2>Recently checked</h2>
          <div class="recent-list">
            {recent.slice(0, 12).map((r) => (
              <a class="recent-row" href={`#/b/${r.sha256}/overview`}>
                <span class="recent-ic"><Icon name={FORMAT_ICON[r.format] ?? 'file'} size={18} /></span>
                <span class="recent-name">{r.file_name}</span>
                <span class="muted small">{FORMAT_WORD[r.format] ?? r.format} · {fmtSize(r.size)}</span>
                <span class="muted small recent-when">{ago(r.created_at)}</span>
              </a>
            ))}
          </div>
        </section>
      )}
    </div>
  );
}
