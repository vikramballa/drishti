// Whole-Mac checks: programs that start automatically, and a quick
// health check of every installed app. Read-only; nothing is changed.
import { useState } from 'preact/hooks';
import { api, AppScan, StartupItem } from '../api';
import { Icon } from '../components/Icon';
import { Term } from '../components/Term';
import { useAsync } from '../components/hooks';
import { go, notify, route } from '../store';

const LEVEL_LABEL: Record<string, string> = { good: 'OK', caution: 'Check', unknown: 'Unknown', info: 'Harmless' };

function signerText(s: StartupItem['signer']): string {
  switch (s.kind) {
    case 'apple': return 'Apple';
    case 'app_store': return 'Mac App Store';
    case 'developer_id': return `${s.developer ?? 'Identified developer'}${s.notarized ? ' · checked by Apple' : ''}`;
    case 'development': return `${s.developer ?? 'Developer'} (test build)`;
    case 'adhoc': return 'No identity';
    case 'unsigned': return 'Not signed';
    default: return 'Unknown';
  }
}

async function openPath(p: string) {
  try {
    const r = await api.openPath(p);
    go({ sha: r.binary_id, view: 'overview', addr: null });
  } catch (e) { notify((e as Error).message, 'error'); }
}

function Startup() {
  const s = useAsync(() => api.startup(), []);
  const items = s.data?.items ?? [];
  const caution = items.filter((i) => i.level === 'caution').length;
  return (
    <section class="checks-sec">
      <h2><Icon name="power" size={18} /> Starts automatically</h2>
      <p class="muted">Programs macOS starts for you, when the Mac starts or when you log in. Unknown entries here are a common sign of unwanted software.</p>
      {s.loading && <div class="skeleton" style={{ height: '120px' }} />}
      {s.error && <div class="banner error">{s.error}</div>}
      {s.data && (
        <p class={`callout ${caution ? 'warn' : 'good'}`}>
          <Icon name={caution ? 'caution' : 'good'} size={16} /> {items.length} item{items.length === 1 ? '' : 's'}; {caution ? `${caution} worth checking.` : 'nothing unusual.'}
        </p>
      )}
      <div class="rows">
        {items.map((i) => (
          <article class={`row lv-${i.level}`}>
            <span class={`pill lv-${i.level}`}>{LEVEL_LABEL[i.level] ?? i.level}</span>
            <div class="row-main">
              <b>{i.app ?? i.label ?? i.file.split('/').pop()}</b>
              <div class="small muted">{i.note}</div>
              <div class="small"><span class="muted">Starts:</span> {i.when}{i.keep_alive ? ' · restarted if it stops' : ''}{i.disabled ? ' · disabled' : ''}</div>
              {i.program && <div class="small mono row-path" title={[i.program, ...i.args].join(' ')}>{[i.program, ...i.args].join(' ')}</div>}
            </div>
            <div class="row-side">
              <span class="small muted">{signerText(i.signer)}</span>
              {i.program && i.level !== 'info' && <button onClick={() => void openPath(i.program!)}>Inspect</button>}
            </div>
          </article>
        ))}
      </div>
      <p class="small muted">To remove an item you don't want, delete its settings file (shown when you hover the path) or uninstall the app that added it. Drishti never changes anything itself.</p>
    </section>
  );
}

function Apps() {
  const [run, setRun] = useState(false);
  const s = useAsync(() => (run ? api.scanApps() : null), [run]);
  const [q, setQ] = useState('');
  const apps = (s.data?.apps ?? []).filter((a) => !q || a.name.toLowerCase().includes(q.toLowerCase()));
  const caution = (s.data?.apps ?? []).filter((a) => a.level === 'caution').length;
  return (
    <section class="checks-sec">
      <h2><Icon name="app" size={18} /> Installed apps</h2>
      <p class="muted">Who made each app, whether Apple checked it (<Term k="notarized">notarized</Term>), what it asks to access, and which tracking or update kits it bundles.</p>
      {!run && <button class="primary" onClick={() => setRun(true)}><Icon name="play" size={15} /> Check all my apps</button>}
      {s.loading && <p class="muted"><span class="spin" /> Reading app signatures… (a few seconds)</p>}
      {s.error && <div class="banner error">{s.error}</div>}
      {s.data && (
        <>
          <p class={`callout ${caution ? 'warn' : 'good'}`}><Icon name={caution ? 'caution' : 'good'} size={16} /> {s.data.apps.length} apps checked; {caution ? `${caution} without a known maker.` : 'all have a known maker.'} Apple's built-in apps are not listed.</p>
          <input type="search" class="wide-input" placeholder="Filter apps…" value={q} onInput={(e) => setQ((e.target as HTMLInputElement).value)} aria-label="Filter apps" />
          <div class="rows">{apps.map((a) => <AppRow a={a} />)}</div>
        </>
      )}
    </section>
  );
}

function AppRow({ a }: { a: AppScan }) {
  return (
    <article class={`row lv-${a.level}`}>
      <span class={`pill lv-${a.level}`}>{LEVEL_LABEL[a.level] ?? a.level}</span>
      <div class="row-main">
        <b>{a.name}</b> {a.version && <span class="muted small">{a.version}</span>}
        <div class="small muted">{signerText(a.signer)}{a.electron ? ' · built with Electron' : ''}{a.login_items ? ' · adds a login item' : ''}</div>
        {(a.access.length > 0 || a.kits.length > 0) && (
          <div class="taglist">
            {a.access.map((x) => <span class="chip">{x}</span>)}
            {a.kits.map((x) => <span class="chip kitchip">{x}</span>)}
          </div>
        )}
      </div>
      <div class="row-side"><button onClick={() => void openPath(a.path)}>Inspect</button></div>
    </article>
  );
}

export function Mac() {
  const tab = route.value.addr === 'apps' ? 'apps' : 'startup';
  return (
    <div class="page mac-page">
      <header class="page-head">
        <div><h1>My Mac</h1><p class="muted">Quick health checks for the whole computer. Drishti only reads; it never changes or removes anything.</p></div>
      </header>
      <div class="seg tabs-seg">
        <a class={`btn${tab === 'startup' ? ' on' : ''}`} href="#/mac/startup">Starts automatically</a>
        <a class={`btn${tab === 'apps' ? ' on' : ''}`} href="#/mac/apps">Installed apps</a>
      </div>
      {tab === 'startup' ? <Startup /> : <Apps />}
    </div>
  );
}
