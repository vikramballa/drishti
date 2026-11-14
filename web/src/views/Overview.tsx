// Summary: the plain-language report a non-expert sees first. One verdict
// with reasons, then who made it, what it can access, who it talks to,
// built-in kits, safety checks and where it came from. The technical
// details (hashes, sections, behaviours…) sit in a collapsed section.
import { useState } from 'preact/hooks';
import { api, fmtSize, Insights, NATIVE, Plain } from '../api';
import { Icon } from '../components/Icon';
import { Term } from '../components/Term';
import { useAsync } from '../components/hooks';
import { DocumentCards, OriginCard } from './Document';
import { askAbout, binary, currentJob, dataVersion, go, goAddr, mode, notify, route, toolVersion } from '../store';

const sevOrder = { high: 0, medium: 1, low: 2, info: 3 } as const;

/** What kind of file this is, in words a non-expert knows. */
export function describeFile(format: string, platform: string, electron: boolean): string {
  if (electron) return 'Desktop app built with web technology (Electron)';
  switch (format) {
    case 'macho': case 'macho-fat': return platform === 'ios' ? 'iPhone / iPad app' : 'Mac program';
    case 'pe': return 'Windows program';
    case 'pe-dotnet': return 'Windows .NET program';
    case 'elf': return platform === 'android' ? 'Android native library' : 'Linux program';
    case 'apk': return 'Android app';
    case 'ipa': return 'iPhone / iPad app package';
    case 'dex': return 'Android app code';
    case 'jar': case 'java-class': return 'Java program';
    case 'pdf': return 'PDF document';
    case 'ooxml': return 'Office document (Word, Excel or PowerPoint)';
    case 'ole': return 'Older Office document';
    case 'wasm': return 'WebAssembly module (code for web pages)';
    case 'asar': return 'Electron app code archive';
    case 'zip': return 'Zip archive';
    case 'archive': return 'Library archive';
    case 'firmware': return 'Firmware';
    default: return 'File';
  }
}

const VERDICT_ICON = { good: 'good', caution: 'caution', danger: 'danger', unknown: 'unknown' } as const;
const TONE_ICON = { bad: 'danger', warn: 'caution', good: 'check', info: 'dot' } as const;

function Verdict({ p, kind, name, sub }: { p: Plain; kind: string; name: string; sub: string }) {
  const v = p.verdict;
  const g = p.grades;
  const sha = route.value.sha!;
  return (
    <section class={`verdict-hero v-${v.level}`}>
      <div class="vh-main">
        <div class="vh-icon"><Icon name={VERDICT_ICON[v.level]} size={30} /></div>
        <div class="vh-text">
          <p class="vh-kind">{kind}</p>
          <h1 class="vh-name" title={name}>{name}</h1>
          <h2 class="vh-title">{v.title}</h2>
          {sub && <p class="vh-sub">{sub}</p>}
        </div>
      </div>
      {v.reasons.length > 0 && (
        <ul class="reasons">
          {v.reasons.map((r) => <li class={`r-${r.tone}`}><Icon name={TONE_ICON[r.tone]} size={16} /><span>{r.text}</span></li>)}
        </ul>
      )}
      {!v.scanned && (
        <p class="vh-hint">
          <Icon name="sparkle" size={15} /> For a stronger answer, <a onClick={() => go({ view: 'checks', addr: null })}>run the safety checks</a> (antivirus, malware patterns{NATIVE.includes(binary.value?.file.format ?? '') ? ', capabilities' : ''}).
        </p>
      )}
      <div class="vh-foot">
        {(g.security || g.privacy || g.trust) && (
          <div class="grades" aria-label="Grades">
            {g.trust && <span class="grade" title="Trust: is the maker known and verified?"><b class={`gr-${g.trust}`}>{g.trust}</b>Trust</span>}
            {g.security && <span class="grade" title="Security: built-in protections against attacks"><b class={`gr-${g.security}`}>{g.security}</b>Security</span>}
            {g.privacy && <span class="grade" title="Privacy: fewer sensitive permissions and tracking kits is better"><b class={`gr-${g.privacy}`}>{g.privacy}</b>Privacy</span>}
          </div>
        )}
        <div class="vh-actions">
          <button class="primary" onClick={() => go({ view: 'ask', addr: null })}><Icon name="ask" size={16} /> Ask about this file</button>
          <button onClick={() => go({ view: 'checks', addr: null })}><Icon name="checks" size={16} /> Safety checks</button>
          <a class="btn ghost" href={api.reportUrl(sha)} download><Icon name="file" size={16} /> Export report</a>
        </div>
      </div>
    </section>
  );
}

function Maker({ p, sha }: { p: Plain; sha: string }) {
  const m = p.maker;
  const [verify, setVerify] = useState<{ busy: boolean; text?: string; ok?: boolean }>({ busy: false });
  const check = async () => {
    setVerify({ busy: true });
    try {
      const r = await api.trust(sha);
      if (!r.available) setVerify({ busy: false, text: r.reason });
      else if (!r.signed) setVerify({ busy: false, text: 'Not signed, so there is nothing to verify.', ok: false });
      else if (r.valid) setVerify({ busy: false, text: 'Verified: the app is exactly as its maker signed it.', ok: true });
      else setVerify({ busy: false, text: `The signature is broken${r.error ? ` (${r.error})` : ''}. The app was changed after it was signed.`, ok: false });
    } catch (e) { setVerify({ busy: false, text: (e as Error).message, ok: false }); }
  };
  const trustLabel: Record<string, string> = { verified: 'Verified maker', signed: 'Signed', weak: 'Unidentified', none: 'Unknown maker', broken: 'Tampered', unknown: 'Not checked', document: 'From the document details' };
  return (
    <section class="card">
      <h3><Icon name="good" size={16} /> Who made it</h3>
      <div class="maker">
        <div class="maker-name">{m.name ?? (m.trust === 'verified' ? 'An identified developer' : 'Unknown')}</div>
        <span class={`pill t-${m.trust}`}>{trustLabel[m.trust] ?? m.trust}</span>
      </div>
      {m.app && <p class="muted small">{[m.app.name, m.app.version && `version ${m.app.version}`, m.app.min_os && `needs macOS ${m.app.min_os}+`].filter(Boolean).join(' · ')}</p>}
      <ul class="plain-list">{m.detail.map((d) => <li>{d}</li>)}</ul>
      {m.trust !== 'none' && m.trust !== 'unknown' && NATIVE.includes(binary.value?.file.format ?? '') && (
        <div class="row-actions">
          <button onClick={check} disabled={verify.busy}>{verify.busy ? 'Checking every file of the app…' : 'Verify the signature'}</button>
        </div>
      )}
      {verify.text && <p class={`small ${verify.ok ? 'ok' : verify.ok === false ? 'bad' : 'muted'}`}>{verify.text}</p>}
    </section>
  );
}

function Permissions({ p }: { p: Plain }) {
  const [open, setOpen] = useState<string | null>(null);
  if (p.permissions.length === 0) return null;
  const sel = p.permissions.find((x) => x.id === open);
  return (
    <section class="card span2">
      <h3><Icon name="key" size={16} /> What it can access</h3>
      <p class="muted small card-lead">From the permissions it asks for and the code it contains. Tap one to see why.</p>
      <div class="perms">
        {p.permissions.map((x) => (
          <button class={`perm${x.sensitive ? ' sensitive' : ''}${open === x.id ? ' on' : ''}`} onClick={() => setOpen(open === x.id ? null : x.id)} aria-expanded={open === x.id}>
            <Icon name={x.icon} size={20} />
            <span>{x.label}</span>
          </button>
        ))}
      </div>
      {sel && (
        <div class="perm-why">
          <b>{sel.label}</b>
          {sel.explanation && <p class="quote">“{sel.explanation}” <span class="muted small">(the developer's explanation)</span></p>}
          <ul class="plain-list">{sel.why.map((w) => <li>{w.charAt(0).toUpperCase() + w.slice(1)}.</li>)}</ul>
        </div>
      )}
    </section>
  );
}

function Network({ p }: { p: Plain }) {
  const n = p.network;
  if (n.groups.length === 0 && n.ips.length === 0) return null;
  return (
    <section class="card">
      <h3><Icon name="globe" size={16} /> Who it talks to</h3>
      <p class="muted small card-lead">Web addresses written inside the file. The app may not contact every one of them.</p>
      {n.groups.map((g) => (
        <details class="netgroup" open={g.id !== 'text' && g.id !== 'other' && g.hosts.length <= 8}>
          <summary><span class={`ng ng-${g.id}`} />{g.label}<span class="count">{g.hosts.length}</span></summary>
          <div class="hostlist">{g.hosts.slice(0, 200).map((h) => <span class="host">{h}</span>)}</div>
        </details>
      ))}
      {n.ips.length > 0 && (
        <details class="netgroup"><summary><span class="ng ng-other" />IP addresses<span class="count">{n.ips.length}</span></summary>
          <div class="hostlist">{n.ips.map((h) => <span class="host">{h}</span>)}</div>
        </details>
      )}
    </section>
  );
}

function Kits({ p }: { p: Plain }) {
  if (p.sdks.length === 0) return null;
  return (
    <section class="card">
      <h3><Icon name="tracker" size={16} /> Built-in kits from other companies</h3>
      <p class="muted small card-lead">Ready-made <Term k="sdk">kits</Term> the developer included. Analytics and ad kits may send data about you to those companies.</p>
      {p.sdks.map((k) => (
        <div class={`kit kc-${k.category}`}>
          <div><b>{k.name}</b><div class="muted small">{k.category_label}</div></div>
          <span class="muted small kit-ev" title={k.evidence.join('; ')}>{k.evidence[0]}</span>
        </div>
      ))}
    </section>
  );
}

function ChecksCard({ sha }: { sha: string }) {
  const tools = useAsync(() => api.fileTools(sha), [sha, toolVersion.value]);
  const looks = useAsync(() => api.lookups(sha), [sha, toolVersion.value]);
  const list = [
    ...(tools.data?.tools ?? []).filter((t) => t.kind === 'safety' && t.installed).map((t) => ({ name: t.name, status: t.status, r: t.result })),
    ...(looks.data?.services ?? []).filter((s) => s.result).map((s) => ({ name: s.name, status: 'done', r: s.result })),
  ];
  return (
    <section class="card">
      <h3><Icon name="checks" size={16} /> Safety checks</h3>
      {list.length === 0 && <p class="muted small">No safety tools are installed yet. See <a href="#/settings/tools">Settings → Tools</a>.</p>}
      {list.map((c) => (
        <div class={`chk v-${c.r?.verdict ?? c.status}`}>
          <span class="chk-dot" />
          <div><b>{c.name}</b><div class="small muted">{c.r ? c.r.headline : c.status === 'running' || c.status === 'queued' ? 'Checking…' : 'Not run yet'}</div></div>
        </div>
      ))}
      <div class="row-actions"><button onClick={() => go({ view: 'checks', addr: null })}>Open safety checks <Icon name="chevron" size={14} /></button></div>
    </section>
  );
}

function HiddenDetails({ sha }: { sha: string }) {
  const tools = useAsync(() => api.fileTools(sha), [sha, toolVersion.value]);
  const ex = tools.data?.tools.find((t) => t.id === 'exiftool')?.result;
  const hl = (ex?.data?.highlights as { label: string; value: string }[] | undefined) ?? [];
  const gps = ex?.data?.gps as { lat: number; lon: number } | null | undefined;
  if (!ex || hl.length === 0) return null;
  return (
    <section class="card">
      <h3><Icon name="details" size={16} /> Hidden details</h3>
      {gps && <p class="callout warn small"><Icon name="location" size={15} /> This file records the place it was made. Anyone you send it to can see it.</p>}
      <dl class="facts">{hl.slice(0, 12).map((h) => <><dt>{h.label}</dt><dd>{h.value}</dd></>)}</dl>
      {gps && <a class="btn ghost small-btn" href={`https://www.openstreetmap.org/?mlat=${gps.lat}&mlon=${gps.lon}#map=15/${gps.lat}/${gps.lon}`} target="_blank" rel="noopener noreferrer"><Icon name="external" size={14} /> Show on a map</a>}
      <div class="row-actions"><button onClick={() => go({ view: 'details', addr: null })}>All details <Icon name="chevron" size={14} /></button></div>
    </section>
  );
}

function AskCard({ kind }: { kind: string }) {
  const s: Record<string, string[]> = {
    pdf: ['Is this PDF safe to open?', 'Where did this PDF come from?', 'Was it changed after it was created?'],
    native: ['What does this program do?', 'Is it safe to run?', 'What can it access on my computer?'],
    other: ['What is this file?', 'Is it safe to open?', 'Where did it come from?'],
  };
  return (
    <section class="card askcard">
      <h3><Icon name="ask" size={16} /> Ask Drishti</h3>
      <p class="small muted card-lead">Plain-English answers based on what Drishti found, with links to the facts behind them.</p>
      <div class="ai-suggest">{(s[kind] ?? s.other).map((q) => <button onClick={() => askAbout(q)}>{q}</button>)}</div>
    </section>
  );
}

export function Overview() {
  const b = binary.value;
  const sha = route.value.sha!;
  const ins = useAsync(() => api.insights(sha), [sha, b?.analysed, dataVersion.value, toolVersion.value]);
  if (!b) return <div class="page"><div class="skeleton hero-sk" /><div class="skeleton-grid"><div class="skeleton" /><div class="skeleton" /><div class="skeleton" /></div></div>;
  const fi = b.file;
  const job = currentJob.value;
  const p = ins.data?.plain;
  const kindTxt = describeFile(fi.format, fi.platform, Boolean(p?.maker.app?.electron));
  const kind = fi.format === 'pdf' ? 'pdf' : NATIVE.includes(fi.format) ? 'native' : 'other';
  const appName = p?.maker.app?.name;
  const ARCH: Record<string, string> = { aarch64: 'Apple Silicon / ARM', x86_64: 'Intel / AMD 64-bit', x86: 'Intel / AMD 32-bit', arm: 'ARM 32-bit' };
  const sub = [fmtSize(fi.size), fi.arch !== 'unknown' ? (ARCH[fi.arch] ?? fi.arch) : null, p?.maker.app?.version ? `version ${p.maker.app.version}` : null].filter(Boolean).join(' · ');
  return (
    <div class="page summary-page">
      {b.load_error && <div class="banner error">{b.load_error}</div>}
      {job && <div class="banner info"><span class="spin" /> Reading the code: {job.phase ?? 'starting'} · {job.functions.toLocaleString()} functions so far. The summary fills in as it finishes.</div>}
      {p ? <Verdict p={p} kind={kindTxt} name={appName ?? fi.file_name} sub={sub} /> : <div class="skeleton hero-sk" />}
      {ins.data && (!NATIVE.includes(fi.format) || mode.value === 'expert') && <p class="summary-text">{ins.data.summary}</p>}
      <div class="grid">
        {p && <Maker p={p} sha={sha} />}
        <ChecksCard sha={sha} />
        {p && <Permissions p={p} />}
        {p && <Network p={p} />}
        {p && <Kits p={p} />}
        {ins.data && (ins.data.origin || ins.data.document) && <OriginCard origin={ins.data.origin} doc={ins.data.document} />}
        <HiddenDetails sha={sha} />
        <AskCard kind={kind} />
      </div>
      {ins.data?.document && <div class="grid"><DocumentCards doc={ins.data.document} /></div>}
      <details class="tech" open={mode.value === 'expert'}>
        <summary><Icon name="code" size={16} /> Technical details <span class="muted small">for experts: fingerprints, sections, code behaviours, findings</span></summary>
        <TechDetails ins={ins.data ?? null} />
      </details>
    </div>
  );
}

const ICON = { good: '✓', bad: '!', info: 'i' } as const;

function TechDetails({ ins }: { ins: Insights | null }) {
  const b = binary.value!;
  const sha = route.value.sha!;
  const fi = b.file;
  const imports = useAsync(() => (b.counts.imports ? api.table(sha, 'imports', '', 0, 20000) : null), [sha, b.counts.imports]);
  const copy = (t: string) => navigator.clipboard?.writeText(t).then(() => notify('Copied', 'ok', undefined, 1200), () => {});
  const caps = new Map<string, string[]>();
  for (const i of imports.data?.items ?? []) if (i.capability) caps.set(i.capability, [...(caps.get(i.capability) ?? []), i.demangled ?? i.name]);
  const libs = new Map<string, number>();
  for (const i of imports.data?.items ?? []) libs.set(i.library ?? '(unknown)', (libs.get(i.library ?? '(unknown)') ?? 0) + 1);
  const maxSec = Math.max(1, ...(b.sections ?? []).map((s) => s.vsize));
  const byKind = new Map<string, Insights['iocs']>();
  for (const i of ins?.iocs ?? []) byKind.set(i.kind, [...(byKind.get(i.kind) ?? []), i]);
  const ent = ins?.signing?.entitlements ?? [];
  return (
    <div class="grid tech-grid">
      <section class="card">
        <h3>Identity</h3>
        <dl class="facts">
          <dt>Format</dt><dd>{fi.format}{fi.arch !== 'unknown' ? ` · ${fi.arch}${fi.bits ? ` ${fi.bits}-bit` : ''}` : ''}{fi.platform !== 'unknown' ? ` · ${fi.platform}` : ''}</dd>
          <dt>Size</dt><dd>{fmtSize(fi.size)}</dd>
          <dt><Term k="sha256">SHA-256</Term></dt><dd class="mono sel-all copy" title="Click to copy" onClick={() => copy(fi.sha256)}>{fi.sha256}</dd>
          <dt><Term k="md5">MD5</Term></dt><dd class="mono sel-all copy" title="Click to copy" onClick={() => copy(fi.md5)}>{fi.md5}</dd>
          <dt><Term k="entropy">Entropy</Term></dt><dd>{fi.entropy.toFixed(3)} / 8</dd>
          {fi.compiler_hints && fi.compiler_hints.length > 0 && <><dt>Built with</dt><dd>{fi.compiler_hints.join(', ')}</dd></>}
          {fi.is_stripped && <><dt>Names</dt><dd><Term k="stripped">stripped</Term></dd></>}
          {fi.is_packed_suspected && <><dt>Packing</dt><dd class="bad"><Term k="packed">packed code suspected</Term></dd></>}
          {fi.entry_point && <><dt>Entry</dt><dd><a class="mono" onClick={() => go({ view: 'code', addr: fi.entry_point! })}>{fi.entry_point}</a></dd></>}
          {b.image_base && <><dt>Image base</dt><dd class="mono">{b.image_base}</dd></>}
        </dl>
      </section>
      {b.analysis && (
        <section class="card">
          <h3>Code analysis</h3>
          <div class="stats">
            <a onClick={() => go({ view: 'functions' })}><b>{b.analysis.functions.toLocaleString()}</b><span><Term k="function">functions</Term></span></a>
            <div><b>{b.analysis.instructions.toLocaleString()}</b><span><Term k="instruction">instructions</Term></span></div>
            <div><b>{b.analysis.xrefs.toLocaleString()}</b><span><Term k="xref">xrefs</Term></span></div>
            <div><b>{b.analysis.jump_tables.toLocaleString()}</b><span>jump tables</span></div>
            <a onClick={() => go({ view: 'imports' })}><b>{(b.counts.imports ?? 0).toLocaleString()}</b><span><Term k="import">imports</Term></span></a>
            <a onClick={() => go({ view: 'strings' })}><b>{b.counts.strings.toLocaleString()}</b><span><Term k="string">strings</Term></span></a>
          </div>
          <p class="muted small">Core engine · {(b.analysis.duration_ms / 1000).toFixed(2)} s</p>
          {fi.entry_point && <button onClick={() => go({ view: 'code', addr: fi.entry_point! })}>Start reading at the entry point</button>}
        </section>
      )}
      {b.findings.length > 0 && (
        <section class="card">
          <h3>Findings</h3>
          {[...b.findings].sort((x, y) => sevOrder[x.severity] - sevOrder[y.severity]).map((f) => (
            <div class={`finding sev-${f.severity}`}><span class="sev">{f.severity}</span><div><b>{f.title}</b><div class="muted">{f.detail}</div>
              {f.addrs && f.addrs.length > 0 && <div class="taglist">{f.addrs.map((a) => <a class="tag" onClick={() => go({ view: 'hex', addr: a })}>{a}</a>)}</div>}
            </div></div>
          ))}
        </section>
      )}
      {ins && ins.hardening.length > 0 && (
        <section class="card">
          <h3>Security <Term k="hardening">hardening</Term></h3>
          {ins.hardening.map((c) => (
            <div class={`check st-${c.status}`}><span class="ci">{ICON[c.status]}</span><div><b>{c.name}</b><div class="muted">{c.detail}</div></div></div>
          ))}
          {ins.signing?.identifier && <p class="muted small">Identifier: <span class="mono">{ins.signing.identifier}</span>{ins.signing.team_id ? ` · Team ${ins.signing.team_id}` : ''}</p>}
        </section>
      )}
      {ins && ins.behaviors.length > 0 && (
        <section class="card">
          <h3>Code behaviours</h3>
          {ins.behaviors.map((bh) => (
            <details class={`beh sev-${bh.severity}`}>
              <summary><span class="sev">{bh.severity}</span> <b>{bh.name}</b> <span class="muted">{bh.function_count ? `${bh.function_count} function${bh.function_count > 1 ? 's' : ''}` : ''}</span></summary>
              <p class="muted small">{bh.description}</p>
              <div class="taglist">{bh.apis.map((a) => <span class="tag">{a}</span>)}</div>
              {bh.functions.length > 0 && <div class="fnlinks">{bh.functions.map((f) => <a class="mono" onClick={() => goAddr(f.entry, 'code')}>{f.name}</a>)}{bh.function_count > bh.functions.length && <span class="muted"> +{bh.function_count - bh.functions.length} more</span>}</div>}
            </details>
          ))}
        </section>
      )}
      {ent.length > 0 && (
        <section class="card">
          <h3><Term k="entitlement">Entitlements</Term> ({ent.length})</h3>
          {ent.map(([k, v]) => <div class="kv"><span class="mono" title={k}>{k.replace('com.apple.', '')}</span><span class="muted" title={v}>{v.length > 28 ? v.slice(0, 26) + '…' : v}</span></div>)}
        </section>
      )}
      {ins && ins.iocs.length > 0 && !ins.document && (
        <section class="card">
          <h3><Term k="ioc">Indicators</Term> in text</h3>
          {[...byKind.entries()].map(([k, v]) => (
            <details open={k === 'url' && v.length < 12}><summary><b>{k}</b> <span class="muted">{v.length}</span></summary>
              <div class="ioclist">{v.map((i) => <a class="mono" title="Show where this string is used" onClick={() => go({ view: 'strings', addr: i.addr })}>{i.value}</a>)}</div>
            </details>
          ))}
        </section>
      )}
      {caps.size > 0 && (
        <section class="card">
          <h3>Capabilities from <Term k="import">imports</Term></h3>
          {[...caps.entries()].map(([c, names]) => (
            <details><summary><b>{c}</b> <span class="muted">{names.length}</span></summary><div class="taglist">{names.slice(0, 80).map((n) => <span class="tag">{n}</span>)}</div></details>
          ))}
        </section>
      )}
      {libs.size > 0 && (
        <section class="card">
          <h3>Libraries</h3>
          {[...libs.entries()].sort((a, c) => c[1] - a[1]).map(([l, n]) => <div class="kv"><span class="mono">{l}</span><span class="muted">{n}</span></div>)}
        </section>
      )}
      {b.sections && b.sections.length > 0 && (
        <section class="card wide">
          <h3><Term k="section">Sections</Term></h3>
          <div class="sections">
            {b.sections.map((s) => (
              <div class="secrow" title={`${s.name} ${s.vaddr} size ${s.vsize} entropy ${s.entropy}`}>
                <span class="sname mono">{s.name}</span>
                <span class="mono muted saddr">{s.vaddr}</span>
                <span class="perm-s mono">{s.perms}</span>
                <span class="bar"><i style={{ width: `${Math.max(1, (100 * s.vsize) / maxSec)}%` }} /></span>
                <span class={`ent${s.entropy > 7.2 ? ' hot' : ''}`} style={{ '--e': s.entropy / 8 } as Record<string, number>}>{s.entropy.toFixed(2)}</span>
              </div>
            ))}
          </div>
        </section>
      )}
      {fi.children && fi.children.length > 0 && (
        <section class="card wide">
          <h3>Contents ({fi.children.length.toLocaleString()})</h3>
          <div class="children">
            {fi.children.slice(0, 500).map((c) => <div class="kv"><span class="mono">{c.path}</span><span class="muted">{c.format} · {fmtSize(c.size)}</span></div>)}
          </div>
        </section>
      )}
      {b.warnings?.map((w) => <div class="banner">{w}</div>)}
    </div>
  );
}
