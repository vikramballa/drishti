// "What changed": compare this binary with another analysed version.
import { useEffect, useState } from 'preact/hooks';
import { api, DiffFn, DiffResult } from '../api';
import { binary, go, route } from '../store';

type Recent = Awaited<ReturnType<typeof api.binaries>>['binaries'];

export function Diff() {
  const sha = route.value.sha!;
  const preset = route.value.addr && /^[0-9a-f]{64}$/.test(route.value.addr) ? route.value.addr : '';
  const [other, setOther] = useState(preset);
  const [recent, setRecent] = useState<Recent>([]);
  const [res, setRes] = useState<DiffResult | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [tab, setTab] = useState<'changed' | 'added' | 'removed'>('changed');
  useEffect(() => { api.binaries().then((r) => setRecent(r.binaries.filter((b) => b.sha256 !== sha && ['elf', 'pe', 'macho', 'macho-fat', 'pe-dotnet'].includes(b.format))), () => {}); }, [sha]);
  useEffect(() => { setOther(preset); }, [preset]);
  useEffect(() => {
    if (!other) { setRes(null); return; }
    let alive = true;
    let tries = 0;
    const run = () => {
      setBusy(true); setErr(null);
      api.diff(sha, other).then(
        (r) => { if (alive) { setRes(r); setBusy(false); if (r.diff.changed.length === 0) setTab(r.diff.added.length ? 'added' : 'removed'); } },
        (e) => {
          if (!alive) return;
          // 409 = the other binary is still being analysed; retry shortly.
          if (e.status === 409 && tries++ < 40) setTimeout(run, 700);
          else { setErr(e.message); setBusy(false); }
        },
      );
    };
    run();
    return () => { alive = false; };
  }, [sha, other]);
  const d = res?.diff;
  const rows: DiffFn[] = d ? d[tab] : [];
  const name = binary.value?.file.file_name;
  return (
    <div class="table-view">
      <div class="code-head">
        <h2>What changed</h2>
        <div class="actions">
          <label class="muted">Compare with (older)&nbsp;
            <select value={other} onChange={(e) => setOther((e.target as HTMLSelectElement).value)} aria-label="Older binary">
              <option value="">Choose a binary…</option>
              {preset && !recent.some((r) => r.sha256 === preset) && <option value={preset}>previous version</option>}
              {recent.map((r) => <option value={r.sha256}>{r.file_name}{r.file_name === name ? ' (same name)' : ''} · {r.sha256.slice(0, 8)}</option>)}
            </select>
          </label>
        </div>
      </div>
      {!other && <div class="empty">Pick an older version of this program to see which functions were added, removed or modified.<br />Open the other file from the home screen first if it is not listed.</div>}
      {busy && <div class="empty">Comparing…</div>}
      {err && <div class="empty">{err}</div>}
      {d && !busy && (
        <>
          <div class="diff-stats">
            <div><b>{d.unchanged.toLocaleString()}</b><span>unchanged</span></div>
            <button class={tab === 'changed' ? 'on' : ''} onClick={() => setTab('changed')}><b class="c-chg">{d.changed.length.toLocaleString()}</b><span>modified</span></button>
            <button class={tab === 'added' ? 'on' : ''} onClick={() => setTab('added')}><b class="c-add">{d.added.length.toLocaleString()}</b><span>added</span></button>
            <button class={tab === 'removed' ? 'on' : ''} onClick={() => setTab('removed')}><b class="c-rem">{d.removed.length.toLocaleString()}</b><span>removed</span></button>
          </div>
          {d.truncated && <div class="fn-count muted">Lists are capped at 2,000 entries each.</div>}
          <div class="listing">
            {rows.length === 0 && <div class="empty">Nothing {tab}.</div>}
            {rows.map((f) => (
              <div class="trow">
                <span class="tval mono">{f.name}</span>
                {f.old && <a class="mono" title="Open in the old version" onClick={() => go({ sha: other, view: 'code', addr: f.old })}>old {f.old}</a>}
                {f.new && <a class="mono" title="Open in this version" onClick={() => go({ view: 'code', addr: f.new })}>new {f.new}</a>}
                <span class="muted tx">{tab === 'changed' ? `${f.old_size} → ${f.new_size} B` : `${f.new_size || f.old_size} B`}</span>
              </div>
            ))}
          </div>
        </>
      )}
    </div>
  );
}
