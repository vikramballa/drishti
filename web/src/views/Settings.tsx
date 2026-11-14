// Settings in sections: General, AI, Tools, Online checks, About.
// API keys are sent once to the Drishti server, which stores them with
// owner-only permissions; the browser never gets them back.
import { useEffect, useState } from 'preact/hooks';
import { AiStatus, api, SecretKey, ToolInfo } from '../api';
import { aiStatus } from '../components/Assistant';
import { Icon } from '../components/Icon';
import { useAsync } from '../components/hooks';
import { applyTheme, mode, notify, route, setMode, theme, toolVersion } from '../store';

const SECTIONS = [
  ['general', 'General', 'settings'],
  ['ai', 'AI assistant', 'ask'],
  ['tools', 'Tools', 'wrench'],
  ['online', 'Online checks', 'cloud'],
  ['about', 'About', 'help'],
] as const;

function KeyField({ k, onChange }: { k: SecretKey; onChange: (keys: SecretKey[]) => void }) {
  const [v, setV] = useState('');
  const [busy, setBusy] = useState(false);
  const save = async () => {
    setBusy(true);
    try { onChange((await api.setSecret(k.id, v.trim())).keys); setV(''); notify(`${k.label} key saved`, 'ok', undefined, 1500); }
    catch (e) { notify((e as Error).message, 'error'); } finally { setBusy(false); }
  };
  const remove = async () => {
    setBusy(true);
    try { onChange((await api.deleteSecret(k.id)).keys); notify('Key removed', 'ok', undefined, 1500); }
    catch (e) { notify((e as Error).message, 'error'); } finally { setBusy(false); }
  };
  return (
    <div class="keyrow">
      <div class="keyrow-t">
        <b>{k.label}</b>
        <span class="small muted">
          {k.set ? <>Saved {k.hint}{k.source === 'environment' ? ` (from ${k.env})` : ''}</> : 'Not set'} · <a href={k.get_url} target="_blank" rel="noopener noreferrer">Get a key <Icon name="external" size={11} /></a>
        </span>
      </div>
      {k.source !== 'environment' && (
        <form class="keyrow-f" onSubmit={(e) => { e.preventDefault(); if (v.trim()) void save(); }}>
          <input type="password" autoComplete="off" placeholder={k.set ? 'Replace key…' : 'Paste key…'} value={v} onInput={(e) => setV((e.target as HTMLInputElement).value)} aria-label={`${k.label} API key`} />
          <button disabled={busy || !v.trim()}>Save</button>
          {k.set && <button type="button" disabled={busy} onClick={() => void remove()}>Remove</button>}
        </form>
      )}
    </div>
  );
}

function General() {
  return (
    <>
      <section class="card">
        <h3>View</h3>
        <p class="small muted card-lead"><b>Simple</b> shows plain-language pages only. <b>Expert</b> adds code, flow graphs, hex and the other technical views.</p>
        <div class="seg">
          <button class={mode.value === 'simple' ? 'on' : ''} onClick={() => setMode('simple')}>Simple</button>
          <button class={mode.value === 'expert' ? 'on' : ''} onClick={() => setMode('expert')}>Expert</button>
        </div>
      </section>
      <section class="card">
        <h3>Appearance</h3>
        <div class="seg">
          {(['system', 'light', 'dark'] as const).map((t) => <button class={theme.value === t ? 'on' : ''} onClick={() => { theme.value = t; applyTheme(); }}>{t === 'system' ? 'Match my Mac' : t === 'light' ? 'Light' : 'Dark'}</button>)}
        </div>
      </section>
      <section class="card">
        <h3>Introduction</h3>
        <p class="small muted card-lead">See the short tour of Drishti again.</p>
        <button onClick={() => { try { localStorage.removeItem('drishti-tour'); } catch { /* ignore */ } location.hash = '#/'; location.reload(); }}>Show the tour</button>
      </section>
      <Token />
    </>
  );
}

function Token() {
  const [tok, setTok] = useState(() => { try { return localStorage.getItem('drishti-token') ?? ''; } catch { return ''; } });
  return (
    <section class="card">
      <h3>Remote server</h3>
      <p class="muted small card-lead">Only needed when this page talks to a Drishti server on another computer. The access token is stored in this browser only.</p>
      <form class="openpath" onSubmit={(e) => { e.preventDefault(); try { localStorage.setItem('drishti-token', tok); } catch { /* ignore */ } location.reload(); }}>
        <input type="password" value={tok} onInput={(e) => setTok((e.target as HTMLInputElement).value)} aria-label="Server access token" />
        <button>Save</button>
      </form>
    </section>
  );
}

function AiSettings() {
  const [st, setSt] = useState<AiStatus | null>(null);
  const [url, setUrl] = useState('');
  const [model, setModel] = useState('');
  const [busy, setBusy] = useState(false);
  const [keys, setKeys] = useState<SecretKey[]>([]);
  const [cloudModels, setCloudModels] = useState<Record<string, string[]>>({});
  const [cloudModel, setCloudModel] = useState('');
  const load = () => aiStatus(true).then((s) => { setSt(s); setUrl(s.url); }, (e: Error) => notify(e.message, 'error'));
  useEffect(() => {
    load();
    api.settings().then((v) => setModel(typeof v['ai.model'] === 'string' ? (v['ai.model'] as string) : ''), () => {});
    api.secrets().then((r) => setKeys(r.keys), () => {});
  }, []);
  const save = async (patch: Record<string, unknown>) => {
    setBusy(true);
    try { await api.saveSettings(patch); await load(); notify('Saved', 'ok', undefined, 1200); } catch (e) { notify((e as Error).message, 'error'); } finally { setBusy(false); }
  };
  const provider = st?.clouds.find((c) => c.id === st.cloud_provider) ?? null;
  useEffect(() => {
    if (!provider) return;
    setCloudModel(provider.model ?? provider.suggested[0] ?? '');
    if (provider.key_set && !cloudModels[provider.id]) {
      api.cloudModels(provider.id).then((r) => setCloudModels((m) => ({ ...m, [provider.id]: r.models })), () => {});
    }
  }, [provider?.id, provider?.key_set]);
  if (!st) return <section class="card"><h3>AI assistant</h3><div class="skeleton" style={{ height: '80px' }} /></section>;
  const localModels = st.models.filter((m) => !st.cloud_models.includes(m));
  const aiKeys = keys.filter((k) => st.clouds.some((c) => c.id === k.id));
  return (
    <>
      <section class="card">
        <h3>AI assistant</h3>
        <div class="statusline"><span class={`dotc ${st.available ? 'ok' : 'off'}`} />{!st.enabled ? 'Turned off' : st.available ? `Ready · ${st.mode === 'cloud' ? `${st.cloud_name} · ${st.active_model}` : `${st.active_model} on this computer`}` : st.error ?? 'Not available'}</div>
        <div class="seg">
          <button class={st.enabled ? 'on' : ''} disabled={busy} onClick={() => save({ 'ai.enabled': true })}>On</button>
          <button class={!st.enabled ? 'on' : ''} disabled={busy} onClick={() => save({ 'ai.enabled': false })}>Off</button>
        </div>
      </section>
      {st.enabled && (
        <section class="card">
          <h3>Where answers come from</h3>
          <div class="choice-row">
            <button class={`opt${st.mode === 'local' ? ' on' : ''}`} onClick={() => save({ 'ai.mode': 'local' })} disabled={busy}>
              <Icon name="lock" size={20} /><b>On this computer</b><span>Free and private. Uses Ollama. Good for simple questions.</span>
            </button>
            <button class={`opt${st.mode === 'cloud' ? ' on' : ''}`} onClick={() => save({ 'ai.mode': 'cloud', 'ai.cloud': st.cloud_provider ?? 'anthropic' })} disabled={busy}>
              <Icon name="cloud" size={20} /><b>Cloud AI with your key</b><span>Smarter answers (Claude, GPT, Gemini…). Sends file facts to that company.</span>
            </button>
          </div>
        </section>
      )}
      {st.enabled && st.mode === 'local' && (
        <section class="card">
          <h3>Local model</h3>
          <div class="statusline"><span class={`dotc ${st.local_available ? 'ok' : 'off'}`} />{st.local_available ? `Ollama is running · ${localModels.length} model${localModels.length === 1 ? '' : 's'}` : 'Ollama is not reachable. Install it from ollama.com and open it.'}</div>
          <label class="small muted" for="ai-model">Model</label>
          <form class="openpath" onSubmit={(e) => { e.preventDefault(); void save({ 'ai.model': model }); }}>
            <select id="ai-model" value={model} onChange={(e) => setModel((e.target as HTMLSelectElement).value)}>
              <option value="">Automatic (best local model)</option>
              {localModels.map((m) => <option value={m}>{m}</option>)}
              {st.cloud_models.length > 0 && <optgroup label="Ollama cloud: sends file facts to Ollama">{st.cloud_models.map((m) => <option value={m}>{m}</option>)}</optgroup>}
            </select>
            <button disabled={busy}>Use</button>
          </form>
          {st.url_editable && (
            <>
              <label class="small muted" for="ai-url">Model server (Ollama, llama.cpp or LM Studio)</label>
              <form class="openpath" onSubmit={(e) => { e.preventDefault(); void save({ 'ai.url': url.trim(), 'ai.provider': url.includes(':11434') ? 'ollama' : 'openai' }); }}>
                <input id="ai-url" value={url} onInput={(e) => setUrl((e.target as HTMLInputElement).value)} placeholder="http://127.0.0.1:11434" />
                <button disabled={busy}>Save</button>
              </form>
            </>
          )}
          <p class="muted small">For a 16 GB Mac: <code>ollama pull qwen3:4b-instruct</code> (2.5 GB, fast). Larger models give better answers but use more memory.</p>
        </section>
      )}
      {st.enabled && st.mode === 'cloud' && (
        <section class="card">
          <h3>Cloud AI</h3>
          <div class="seg wrap">
            {st.clouds.map((c) => <button class={c.id === st.cloud_provider ? 'on' : ''} onClick={() => save({ 'ai.cloud': c.id })} disabled={busy}>{c.name}{c.key_set ? ' ✓' : ''}</button>)}
          </div>
          {provider && (
            <>
              {aiKeys.filter((k) => k.id === provider.id).map((k) => <KeyField k={k} onChange={(ks) => { setKeys(ks); void load(); }} />)}
              <label class="small muted" for="cloud-model">Model</label>
              <form class="openpath" onSubmit={(e) => { e.preventDefault(); void save({ [`ai.cloud_model.${provider.id}`]: cloudModel.trim() }); }}>
                <input id="cloud-model" list="cloud-models" value={cloudModel} placeholder={provider.suggested[0] ?? 'model id'} onInput={(e) => setCloudModel((e.target as HTMLInputElement).value)} />
                <datalist id="cloud-models">{[...new Set([...provider.suggested, ...(cloudModels[provider.id] ?? [])])].map((m) => <option value={m} />)}</datalist>
                <button disabled={busy || !cloudModel.trim()}>Use</button>
              </form>
              {provider.id === 'anthropic' && <p class="small muted">Suggested: <b>claude-sonnet-5-5</b> (balanced), <b>claude-opus-5-5</b> (most thorough), <b>claude-haiku-5-5</b> (fastest, cheapest).</p>}
            </>
          )}
          <div class={`consent${st.cloud_consent ? ' ok' : ''}`}>
            <p><b>What gets sent:</b> your question plus a summary Drishti made of the file (its name, type, findings, text found inside it, addresses, and for code questions the instructions of one function). <b>The file itself is never uploaded.</b> Files you mark as <i>private</i> always stay on this computer.</p>
            <label class="check-row"><input type="checkbox" checked={st.cloud_consent} onChange={(e) => save({ 'ai.cloud_consent': (e.target as HTMLInputElement).checked })} /> I understand and want to use cloud AI</label>
          </div>
        </section>
      )}
    </>
  );
}

function ToolsSettings() {
  const t = useAsync(() => api.tools(), [toolVersion.value]);
  const copy = (s: string) => navigator.clipboard?.writeText(s).then(() => notify('Copied. Paste it into Terminal.', 'ok', undefined, 2000), () => {});
  const setup = async (tool: ToolInfo) => {
    try { await api.setupTool(tool.id); notify(`${tool.setup?.action}: started. This can take a few minutes.`, 'info'); toolVersion.value++; }
    catch (e) { notify((e as Error).message, 'error'); }
  };
  useEffect(() => {
    if (!t.data) return;
    if (!Object.values(t.data.tasks).some((x) => x.status === 'running' || x.status === 'queued')) return;
    const id = setTimeout(() => { toolVersion.value++; }, 2500);
    return () => clearTimeout(id);
  }, [t.data]);
  if (!t.data) return <div class="skeleton" style={{ height: '200px' }} />;
  const kinds: [string, string][] = [['decompiler', 'Readable code'], ['safety', 'Safety'], ['details', 'Hidden details'], ['apps', 'Other kinds of apps']];
  return (
    <>
      <section class="card">
        <h3>How tools run</h3>
        <p class="small">{t.data.sandbox
          ? <>Each tool runs in a <b>macOS sandbox</b>: no internet, and it can only write to its own folder. Tools only read the file; Drishti never runs it.</>
          : <>No sandbox is available on this system, so tools are disabled for safety.</>}</p>
        <p class="small muted">Install missing tools with the command shown (copy it, then paste it into Terminal). Everything is free and open source.</p>
      </section>
      {kinds.map(([k, label]) => (
        <section class="card">
          <h3>{label}</h3>
          {t.data!.tools.filter((x) => x.kind === k).map((x) => {
            const task = x.setup ? t.data!.tasks[`setup:${x.setup.id}`] : undefined;
            const running = task && (task.status === 'running' || task.status === 'queued');
            return (
              <div class="toolrow">
                <span class={`dotc ${x.installed ? (x.setup && !x.setup.ready ? 'warn' : 'ok') : 'off'}`} />
                <div class="toolrow-t">
                  <b>{x.name}</b> {x.version && <span class="muted small">{x.version}</span>}
                  <div class="small muted">{x.what}</div>
                  {!x.installed && <div class="small"><code class="copy" onClick={() => copy(x.install)} title="Click to copy">{x.install}</code></div>}
                  {x.id === 'ghidra' && x.installed && !x.java_ok && <div class="small bad">Needs Java 25: <code class="copy" onClick={() => copy('brew install openjdk@25')}>brew install openjdk@25</code></div>}
                  {x.id === 'radare2' && x.installed && x.extra && x.extra.r2ghidra === false && <div class="small muted">Better output: <code class="copy" onClick={() => copy('r2pm -ci r2ghidra')}>r2pm -ci r2ghidra</code></div>}
                  {x.installed && x.setup && (
                    <div class="small setupline">
                      {x.setup.ready ? <span class="ok">✓ {x.setup.label} ready{x.setup.version ? ` (${x.setup.version})` : ''}{x.setup.age_days != null ? `, ${x.setup.age_days} days old` : ''}</span> : <span class="warn-t">{x.setup.label} not downloaded yet.</span>}
                      {' '}<button disabled={running} onClick={() => void setup(x)}>{running ? 'Working…' : x.setup.ready ? 'Update' : x.setup.action}</button>
                      {task?.status === 'failed' && <div class="bad">{task.error}</div>}
                    </div>
                  )}
                </div>
                <a class="small muted" href={x.homepage} target="_blank" rel="noopener noreferrer" title={`${x.license} licence`}><Icon name="external" size={13} /></a>
              </div>
            );
          })}
        </section>
      ))}
    </>
  );
}

function OnlineSettings() {
  const [on, setOn] = useState<boolean | null>(null);
  const [keys, setKeys] = useState<SecretKey[]>([]);
  useEffect(() => {
    api.settings().then((v) => setOn(v['online.enabled'] === true || v['online.enabled'] === 'true'), () => setOn(false));
    api.secrets().then((r) => setKeys(r.keys), () => {});
  }, []);
  const toggle = async (v: boolean) => {
    try { await api.saveSettings({ 'online.enabled': v }); setOn(v); } catch (e) { notify((e as Error).message, 'error'); }
  };
  const ids = ['virustotal', 'abusech', 'abuseipdb'];
  return (
    <>
      <section class="card">
        <h3>Online checks</h3>
        <p class="small">Ask public security databases whether a file, or the addresses inside it, are known to be bad. Checks run only when you press <b>Check</b> on a file.</p>
        <ul class="plain-list small">
          <li><b>VirusTotal</b> and <b>MalwareBazaar</b> receive only the file's fingerprint (SHA-256), never the file.</li>
          <li><b>URLhaus</b> receives the web domain names found inside the file.</li>
          <li><b>AbuseIPDB</b> receives the public IP addresses found inside the file.</li>
        </ul>
        <label class="check-row"><input type="checkbox" checked={Boolean(on)} disabled={on === null} onChange={(e) => void toggle((e.target as HTMLInputElement).checked)} /> Allow online checks</label>
      </section>
      <section class="card">
        <h3>Free API keys</h3>
        <p class="small muted card-lead">Each service gives free keys after signing up. Keys are stored on this computer only (owner-only file), never shown again in full.</p>
        {keys.filter((k) => ids.includes(k.id)).map((k) => <KeyField k={k} onChange={setKeys} />)}
      </section>
    </>
  );
}

function About() {
  return (
    <section class="card">
      <h3>About Drishti</h3>
      <p>Drishti shows what a program or document really is, whether it looks safe and where it came from. The core engine is written in Rust and nothing you open is ever executed.</p>
      <p class="muted small">Drishti is for education, security research, malware analysis, interoperability and analysis of software you own or are permitted to analyse. Reverse engineering may be restricted by licence agreements, copyright and anti-circumvention laws, which vary by country; you are responsible for complying with them. Drishti does not include features for removing licence checks or DRM, or for decrypting protected app-store binaries.</p>
      <p class="small">Use Drishti from Claude Code: <code>claude mcp add drishti -- drishti mcp</code></p>
    </section>
  );
}

export function Settings() {
  const sec = (SECTIONS.find(([id]) => id === route.value.addr)?.[0]) ?? 'general';
  return (
    <div class="page settings-page">
      <header class="page-head"><div><h1>Settings</h1></div></header>
      <div class="settings-layout">
        <nav class="settings-nav" aria-label="Settings sections">
          {SECTIONS.map(([id, label, icon]) => <a class={sec === id ? 'on' : ''} href={`#/settings/${id}`}><Icon name={icon} size={16} />{label}</a>)}
        </nav>
        <div class="settings-body">
          {sec === 'general' && <General />}
          {sec === 'ai' && <AiSettings />}
          {sec === 'tools' && <ToolsSettings />}
          {sec === 'online' && <OnlineSettings />}
          {sec === 'about' && <About />}
        </div>
      </div>
    </div>
  );
}
