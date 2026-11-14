// Disassembly: the current function as an address-ordered listing with
// labels, branch links, comments and an xref/callee side panel.
import { useEffect, useMemo, useState } from 'preact/hooks';
import { api, Decompiled, FunctionDetail, Insn } from '../api';
import { Assistant } from '../components/Assistant';
import { Icon } from '../components/Icon';
import { Term } from '../components/Term';
import { useAsync } from '../components/hooks';
import { mnemonicHelp } from '../components/mnemonics';
import { binary, dataVersion, go, goAddr, isMobile, notify, refreshData, route } from '../store';

const HEXRE = /(0x[0-9a-f]+)/gi;

export function Operands({ ins }: { ins: Insn }) {
  const targets = new Set((ins.targets ?? []).map((t) => BigInt(t)));
  const parts = ins.operands.split(HEXRE);
  return (
    <span class="ops">
      {parts.map((p, i) => {
        if (i % 2 === 1) {
          let v: bigint | null = null;
          try { v = BigInt(p); } catch { /* not a number */ }
          if (v !== null && (targets.has(v) || v > 0x1000n)) {
            const a = '0x' + v.toString(16);
            return <a class={targets.has(v) ? 'tgt' : 'num'} href={`#/b/${route.value.sha}/code?a=${a}`} onClick={(e) => { e.preventDefault(); goAddr(a); }}>{p}</a>;
          }
          return <span class="num">{p}</span>;
        }
        return p;
      })}
    </span>
  );
}

export function InsnRow({ ins, selected, onSelect, showBytes }: { ins: Insn; selected: boolean; onSelect: (a: string) => void; showBytes: boolean }) {
  const help = mnemonicHelp(ins.mnemonic, binary.value?.file.arch);
  return (
    <>
      <div class={`insn k-${ins.kind}${selected ? ' sel' : ''}`} onClick={() => onSelect(ins.addr)} data-addr={ins.addr}>
        <span class="ia">{ins.addr.replace(/^0x/, '')}</span>
        {showBytes && <span class="ib">{ins.bytes}</span>}
        <span class="im" title={help}>{ins.mnemonic}</span>
        <Operands ins={ins} />
        {ins.comment && (
          <span class="ic" onClick={(e) => { if (ins.targets?.length) { e.stopPropagation(); goAddr(ins.targets[0]); } }}>; {ins.comment}</span>
        )}
      </div>
      {selected && help && <div class="ihelp">{ins.mnemonic} — {help}</div>}
    </>
  );
}

async function promptAnnotate(sha: string, addr: string, kind: 'rename_function' | 'comment', current: string) {
  const v = window.prompt(kind === 'comment' ? `Comment at ${addr}` : `Rename function at ${addr}`, current);
  if (v === null) return;
  try {
    await api.annotate(sha, addr, kind, v);
    refreshData(sha);
    notify(kind === 'comment' ? 'Comment saved' : `Renamed to ${v}`, 'ok');
  } catch (e) {
    notify((e as Error).message, 'error');
  }
}

export function Code() {
  const sha = route.value.sha!;
  const b = binary.value;
  const addr = route.value.addr ?? b?.file.entry_point ?? null;
  const [sel, setSel] = useState<string | null>(addr);
  const fn = useAsync(() => (addr && b?.analysed ? api.fn(sha, addr) : null), [sha, addr, b?.analysed, dataVersion.value]);
  const raw = useAsync(() => (addr && (fn.error || (b && !b.analysed)) ? api.disasm(sha, addr, 400) : null), [sha, addr, fn.error, b?.analysed, dataVersion.value]);
  const showBytes = !isMobile.value;

  if (!addr) return <div class="empty">No entry point. Pick a function or use Go to.</div>;
  if (fn.loading && !fn.data) return <div class="empty">Loading…</div>;

  if (!fn.data) {
    const d = raw.data;
    return (
      <div class="code">
        <div class="code-head"><h2>{d?.function?.name ?? addr}</h2><span class="muted">{d?.section ?? ''} · raw listing</span></div>
        <div class="listing">{d?.instructions.map((i) => <InsnRow ins={i} selected={i.addr === sel} onSelect={setSel} showBytes={showBytes} />)}</div>
      </div>
    );
  }
  return <FunctionListing f={fn.data} sel={sel} setSel={setSel} showBytes={showBytes} />;
}

/** C-like code for one function from Ghidra or radare2 (polled while it runs). */
function Readable({ sha, entry }: { sha: string; entry: string }) {
  const [engine, setEngine] = useState<string | undefined>(() => { try { return localStorage.getItem('drishti-decomp') ?? undefined; } catch { return undefined; } });
  const [d, setD] = useState<Decompiled | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [tick, setTick] = useState(0);
  useEffect(() => {
    let alive = true;
    setErr(null);
    api.decompile(sha, entry, engine).then((r) => { if (alive) setD(r); }, (e: Error) => alive && setErr(e.message));
    return () => { alive = false; };
  }, [sha, entry, engine, tick]);
  useEffect(() => {
    if (!d || (d.status !== 'queued' && d.status !== 'running')) return;
    const id = setTimeout(() => setTick((t) => t + 1), 1500);
    return () => clearTimeout(id);
  }, [d]);
  const pick = (e: string) => { setEngine(e); setD(null); try { localStorage.setItem('drishti-decomp', e); } catch { /* ignore */ } };
  const busy = d && (d.status === 'queued' || d.status === 'running');
  return (
    <div class="readable">
      <div class="readable-head">
        <span class="small muted"><Term k="decompiler">Decompiled</Term> by</span>
        <div class="seg small-seg">
          {['ghidra', 'radare2'].map((e) => <button class={(d?.engine ?? engine) === e ? 'on' : ''} onClick={() => pick(e)}>{e === 'ghidra' ? 'Ghidra' : 'radare2'}</button>)}
        </div>
        {d?.status === 'done' && <span class="small muted">{d.duration_ms != null ? `${(d.duration_ms / 1000).toFixed(1)} s` : ''}{d.quality === 'basic' ? ' · basic output (install r2ghidra for better)' : ''}</span>}
      </div>
      {err && <p class="bad small pad">{err}</p>}
      {!d && !err && <div class="skeleton" style={{ margin: '12px', height: '160px' }} />}
      {busy && (
        <p class="pad muted"><span class="spin" /> {d!.first_time ? 'Ghidra is loading this program for the first time. Large apps take a minute or two; later functions take a few seconds.' : `Decompiling… ${d!.elapsed_s ? `${d!.elapsed_s} s` : ''}`}</p>
      )}
      {d?.status === 'missing' && <p class="pad small">{d.message} <code>{d.install}</code></p>}
      {d?.status === 'failed' && <p class="pad small bad">{d.message ?? 'Failed'} <button onClick={() => setTick((t) => t + 1)}>Try again</button></p>}
      {d?.status === 'done' && <pre class="codeblock c-code">{d.code}</pre>}
      <p class="small muted pad">Names like <span class="mono">iVar1</span> and <span class="mono">local_58</span> are made up by the decompiler; the logic is real.</p>
    </div>
  );
}

function FunctionListing({ f, sel, setSel, showBytes }: { f: FunctionDetail; sel: string | null; setSel: (a: string) => void; showBytes: boolean }) {
  const sha = route.value.sha!;
  const [panel, setPanel] = useState(!isMobile.value);
  const [explain, setExplain] = useState(false);
  const [view, setView] = useState<'asm' | 'c'>(() => { try { return (localStorage.getItem('drishti-codeview') as 'asm' | 'c') || 'asm'; } catch { return 'asm'; } });
  const pickView = (v: 'asm' | 'c') => { setView(v); try { localStorage.setItem('drishti-codeview', v); } catch { /* ignore */ } };
  const blocks = useMemo(() => [...f.blocks].sort((a, b) => (BigInt(a.start) < BigInt(b.start) ? -1 : 1)), [f]);
  const xrefs = useAsync(() => (sel && sel !== f.entry ? api.xrefsTo(sha, sel) : null), [sha, sel]);
  useEffect(() => {
    if (sel && sel !== f.entry) document.querySelector(`.listing [data-addr="${sel}"]`)?.scrollIntoView({ block: 'center' });
  }, [f]);
  return (
    <div class="code">
      <div class="code-head">
        <h2 title={f.original_name}>{f.name}</h2>
        <span class="muted">{f.entry} · {f.size} bytes · {f.metrics.block_count} blocks · CC {f.metrics.cyclomatic}{f.is_thunk ? ' · thunk' : ''}{f.noreturn ? ' · noreturn' : ''}</span>
        <div class="seg small-seg" role="tablist" aria-label="Code view">
          <button role="tab" aria-selected={view === 'asm'} class={view === 'asm' ? 'on' : ''} onClick={() => pickView('asm')}><Term k="disassembly">Instructions</Term></button>
          <button role="tab" aria-selected={view === 'c'} class={view === 'c' ? 'on' : ''} onClick={() => pickView('c')}>Readable code</button>
        </div>
        <div class="actions">
          <button class="primary" onClick={() => setExplain(true)} title="Plain-language explanation from the AI"><Icon name="sparkle" size={14} /> Explain</button>
          <button onClick={() => promptAnnotate(sha, f.entry, 'rename_function', f.name)}>Rename</button>
          <button onClick={() => sel && promptAnnotate(sha, sel, 'comment', '')} disabled={!sel}>Comment</button>
          <button onClick={() => go({ view: 'graph', addr: f.entry })}>Graph</button>
          <button onClick={() => go({ view: 'hex', addr: sel ?? f.entry })}>Hex</button>
          <button class={panel ? 'on' : ''} onClick={() => setPanel(!panel)}>Refs</button>
        </div>
      </div>
      <div class="code-body">
        {view === 'c' && <div class="listing c-listing"><Readable sha={sha} entry={f.entry} />{explain && (
            <div class="sheet center" onClick={() => setExplain(false)}>
              <div class="ai-sheet" onClick={(e) => e.stopPropagation()}>
                <Assistant sha={sha} kind="fn" addr={f.entry} fnName={f.name} autoAsk="Explain what this function does in simple words." />
                <button onClick={() => setExplain(false)}>Close</button>
              </div>
            </div>
          )}</div>}
        <div class="listing" hidden={view === 'c'}>
          {blocks.map((b) => (
            <div class="blk" key={b.start}>
              <div class="lbl">{b.start === f.entry ? f.name : `loc_${b.start.replace(/^0x/, '')}`}:</div>
              {b.instructions.map((i) => <InsnRow ins={i} selected={i.addr === sel} onSelect={setSel} showBytes={showBytes} />)}
              {b.successors.length > 0 && (
                <div class="succ">
                  {b.successors.map((s) => (
                    <a class={`edge e-${s.kind}`} onClick={() => { setSel(s.target); document.querySelector(`[data-addr="${s.target}"]`)?.scrollIntoView({ block: 'center' }); }}>
                      {s.kind} → {s.target.replace(/^0x/, '')}
                    </a>
                  ))}
                </div>
              )}
            </div>
          ))}
          {f.truncated && <div class="muted pad">Listing truncated (very large function).</div>}
          {explain && (
            <div class="sheet center" onClick={() => setExplain(false)}>
              <div class="ai-sheet" onClick={(e) => e.stopPropagation()}>
                <Assistant sha={sha} kind="fn" addr={f.entry} fnName={f.name} autoAsk="Explain what this function does in simple words." />
                <button onClick={() => setExplain(false)}>Close</button>
              </div>
            </div>
          )}
        </div>
        {panel && (
          <aside class="refs">
            {sel && sel !== f.entry && xrefs.data && xrefs.data.items.length > 0 && (
              <section><h3>Xrefs to {sel}</h3>{xrefs.data.items.slice(0, 50).map((x) => <a onClick={() => goAddr(x.from)}>{x.from} <span class="muted">{x.kind} {x.function?.name ?? ''}</span></a>)}</section>
            )}
            <section><h3>Callers ({f.callers.length})</h3>{f.callers.slice(0, 200).map((c) => <a onClick={() => goAddr(c.addr)}>{c.name ?? c.addr}</a>)}</section>
            <section><h3>Calls ({f.callees.length})</h3>{f.callees.slice(0, 200).map((c) => <a onClick={() => goAddr(c.addr)}>{c.name ?? c.addr}</a>)}</section>
            {f.strings.length > 0 && <section><h3>Strings ({f.strings.length})</h3>{f.strings.slice(0, 200).map((s) => <a onClick={() => { setSel(s.from); document.querySelector(`[data-addr="${s.from}"]`)?.scrollIntoView({ block: 'center' }); }} title={s.value}>"{s.value}"</a>)}</section>}
            <section><h3>Xrefs to function ({f.xrefs_to.length})</h3>{f.xrefs_to.slice(0, 200).map((x) => <a onClick={() => goAddr(x.from)}>{x.from} <span class="muted">{x.kind}</span></a>)}</section>
          </aside>
        )}
      </div>
    </div>
  );
}
