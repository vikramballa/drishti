// Weak spots: a static "where could untrusted input reach something
// dangerous?" audit. Each finding leads with a plain sentence, a confidence
// badge, and the call path, and links straight to the code (Expert mode).
import { useState } from 'preact/hooks';
import { api, VulnFinding } from '../api';
import { Icon } from '../components/Icon';
import { Term } from '../components/Term';
import { useAsync } from '../components/hooks';
import { goAddr, mode, route, setMode } from '../store';

const CONF_LABEL: Record<string, string> = {
  high: 'input reaches it in the same function',
  medium: 'reachable from input via a call path',
  low: 'unsafe call, no input path found',
};

function goCode(addr: string) {
  if (mode.value !== 'expert') setMode('expert');
  goAddr(addr, 'code');
}

function Finding({ f }: { f: VulnFinding }) {
  const [open, setOpen] = useState(false);
  return (
    <li class={`sev-${f.severity}`}>
      <span class="sevdot" />
      <div class="grow">
        <b>{f.title}</b>
        <span class={`conf conf-${f.confidence}`} title={CONF_LABEL[f.confidence]}>{f.confidence} confidence</span>
        <div class="muted small">{f.explanation}</div>
        <div class="small">
          in <a class="mono" href="#" onClick={(e) => { e.preventDefault(); goCode(f.sink_fn.entry); }}>{f.sink_fn.name}</a>
          {f.source_fn && f.source_fn.entry !== f.sink_fn.entry && (
            <> · input in <a class="mono" href="#" onClick={(e) => { e.preventDefault(); goCode(f.source_fn!.entry); }}>{f.source_fn.name}</a></>
          )}
        </div>
        {f.path.length > 1 && (
          <div class="small vpath">
            {open ? (
              <span class="mono">{f.path.map((p, i) => (
                <>{i > 0 && <span class="muted"> → </span>}<a href="#" onClick={(e) => { e.preventDefault(); goCode(p.entry); }}>{p.name}</a></>
              ))}</span>
            ) : (
              <button class="link" onClick={() => setOpen(true)}>Show call path ({f.path.length} steps)</button>
            )}
          </div>
        )}
      </div>
    </li>
  );
}

export function WeakSpots() {
  const sha = route.value.sha!;
  const { data, error, loading } = useAsync(() => api.vulns(sha), [sha]);
  const [showLow, setShowLow] = useState(false);

  if (loading) return <div class="pad"><div class="skeleton-list" /></div>;
  if (error) return <div class="pad"><p class="muted">Weak-spot analysis needs the code to be analysed first. {error}</p></div>;
  if (!data) return null;

  const findings = data.findings.filter((f) => showLow || f.confidence !== 'low');
  const lowCount = data.findings.filter((f) => f.confidence === 'low').length;

  return (
    <div class="pad weakspots">
      <header class="view-head">
        <h2><Icon name="checks" size={20} /> Weak spots</h2>
        <p class="muted">
          Places where <Term k="untrusted input">data from outside the program</Term> could reach a risky
          operation. This is a map for a closer look, <b>not proof of a bug</b>.
        </p>
      </header>

      {data.findings.length === 0 ? (
        <p class="muted">No input-to-dangerous-operation paths were found among {data.scanned_functions.toLocaleString()} functions. That does not guarantee the program is safe — it means nothing matched these patterns.</p>
      ) : (
        <>
          <p class="small muted">
            {data.findings.length} potential weak spot(s) · {data.sources_found} input source(s) · {data.scanned_functions.toLocaleString()} functions scanned.
          </p>
          <ul class="items vuln-list">
            {findings.map((f) => <Finding f={f} />)}
          </ul>
          {lowCount > 0 && !showLow && (
            <button class="link" onClick={() => setShowLow(true)}>Show {lowCount} lower-confidence item(s) (unsafe calls with no input path)</button>
          )}
        </>
      )}

      <p class="small muted result-foot">
        How this works: Drishti follows the call graph from functions that read input
        (<span class="mono">recv, read, fread, getenv…</span>) to functions that call something dangerous
        (<span class="mono">system, exec, strcpy, sprintf, memcpy, dlopen…</span>). A path means the data
        <em> could</em> reach that call — confirm it by reading the code. Exact value tracking is coming with
        the built-in decompiler.
      </p>
    </div>
  );
}
