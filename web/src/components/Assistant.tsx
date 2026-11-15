// "Ask Drishti": plain-language Q&A about the open file. Answers come from
// a model on this computer (Ollama) or, if the person chose it, a cloud
// model with their own key. Answers stream in, cite the facts they rely on
// as [F12] (tap to see the fact), and the conversation is kept per file
// (and per function) while the page is open.
import type { JSX } from 'preact';
import { useEffect, useRef, useState } from 'preact/hooks';
import { AiClaim, AiStatus, api, ChatTurn } from '../api';
import { Icon } from './Icon';
import { notify } from '../store';

let statusP: Promise<AiStatus> | null = null;
export function aiStatus(refresh = false): Promise<AiStatus> {
  if (refresh || !statusP) {
    statusP = api.aiStatus();
    statusP.catch(() => { statusP = null; });
  }
  return statusP;
}

const chats = new Map<string, ChatTurn[]>();

const SUGGEST: Record<string, string[]> = {
  pdf: ['Is this PDF safe to open?', 'Where did this PDF come from?', 'Who made it, and when?', 'Was it changed after it was created?'],
  native: ['What does this program do?', 'Is it safe to run?', 'What can it access on my computer?', 'Does it connect to the internet?', 'Does it track me?'],
  fn: ['Explain what this function does in simple words.', 'Is anything in this function suspicious?', 'What would be a better name for it?'],
  other: ['What is this file?', 'Is it safe to open?', 'Where did it come from?'],
};

type Level = 'simple' | 'normal' | 'expert';
function readLevel(): Level {
  try { return (localStorage.getItem('drishti-ai-level') as Level) || 'normal'; } catch { return 'normal'; }
}

/** Hide a model's private reasoning (`<think>…</think>`), even mid-stream. */
function visible(t: string): string {
  const s = t.replace(/<think>[\s\S]*?<\/think>/g, '');
  const open = s.indexOf('<think>');
  return (open >= 0 ? s.slice(0, open) : s).trimStart();
}

/** While streaming, hide the machine-readable `<claims>` block (and a tag
 *  that is still arriving, like `<cla`). The server parses it at the end. */
function shown(t: string): string {
  const v = visible(t);
  const at = v.toLowerCase().indexOf('<claims>');
  let s = at >= 0 ? v.slice(0, at) : v;
  const lt = s.lastIndexOf('<');
  if (lt >= 0 && '<claims>'.startsWith(s.slice(lt).toLowerCase())) s = s.slice(0, lt);
  // A block wrapped in a code fence leaves an unclosed "```" behind.
  if ((s.match(/```/g)?.length ?? 0) % 2) s = s.replace(/```[a-z]*\s*$/i, '');
  return s.trimEnd();
}

const KIND: Record<AiClaim['kind'], string> = { calls: 'Calls', imports: 'Imports', string: 'Text', address: 'Address', function: 'Function' };

const BADGE = { verified: 'Verified', refuted: 'Wrong', unverified: 'Unverified' } as const;

/** The concrete things an answer claims, each checked against the file. */
function Claims({ claims }: { claims: AiClaim[] }) {
  const n = (st: string) => claims.filter((c) => (c.status ?? 'unverified') === st).length;
  const bad = n('refuted');
  const parts = [n('verified') && `${n('verified')} verified`, bad && `${bad} wrong`, n('unverified') && `${n('unverified')} unverified`].filter(Boolean).join(', ');
  return (
    <>
      {bad > 0 && <p class="claim-warn"><b>Check this answer:</b> {bad === 1 ? 'one thing it says does' : `${bad} things it says do`} not match the file.</p>}
      <details class="ai-claims" open={bad > 0}>
        <summary>What this answer claims ({claims.length}) · <span class="muted">{parts}</span></summary>
        <ul>
          {claims.map((c) => {
            const st = c.status ?? 'unverified';
            return (
              <li title={c.reason ?? 'Not checked.'}>
                <span class={`claim-badge ${st}`}>{BADGE[st]}</span>
                <span class="claim-kind">{KIND[c.kind] ?? c.kind}</span> <code>{c.subject ? `${c.subject} → ${c.target}` : c.target}</code>
                {c.reason && <span class="claim-reason">{c.reason}</span>}
              </li>
            );
          })}
        </ul>
      </details>
    </>
  );
}

type Cite = (id: number) => void;

function inline(t: string, cite?: Cite) {
  const out: (string | JSX.Element)[] = [];
  const re = /(\*\*[^*]+\*\*|`[^`]+`|\[F\d+(?:\s*,\s*F?\d+)*\])/g;
  let last = 0;
  for (const m of t.matchAll(re)) {
    if (m.index! > last) out.push(t.slice(last, m.index));
    const x = m[0];
    if (x.startsWith('[F')) {
      const ids = x.slice(1, -1).split(',').map((s) => Number(s.trim().replace(/^F/, ''))).filter((n) => n > 0);
      out.push(<>{ids.map((n) => <button type="button" class="cite" onClick={() => cite?.(n)} title="Show the fact this is based on">{n}</button>)}</>);
    } else {
      out.push(x.startsWith('**') ? <b>{x.slice(2, -2)}</b> : <code>{x.slice(1, -1)}</code>);
    }
    last = m.index! + x.length;
  }
  out.push(t.slice(last));
  return out;
}

/** Minimal, safe Markdown: paragraphs, bullets, numbered lists, bold, code, citations. */
export function Prose({ text, cite }: { text: string; cite?: Cite }) {
  const blocks: JSX.Element[] = [];
  let list: { ordered: boolean; items: string[] } | null = null;
  const flush = () => {
    if (!list) return;
    const items = list.items.map((i) => <li>{inline(i, cite)}</li>);
    blocks.push(list.ordered ? <ol>{items}</ol> : <ul>{items}</ul>);
    list = null;
  };
  for (const raw of text.split('\n')) {
    const line = raw.trimEnd();
    const bullet = /^\s*(?:[-*•])\s+(.*)$/.exec(line);
    const num = /^\s*\d+[.)]\s+(.*)$/.exec(line);
    if (bullet || num) {
      const ordered = Boolean(num);
      if (!list || list.ordered !== ordered) { flush(); list = { ordered, items: [] }; }
      list.items.push((bullet ?? num)![1]);
      continue;
    }
    flush();
    if (!line.trim() || /^-{3,}$/.test(line.trim())) continue;
    const h = /^#{1,6}\s+(.*)$/.exec(line);
    blocks.push(h ? <p><b>{inline(h[1], cite)}</b></p> : <p>{inline(line, cite)}</p>);
  }
  flush();
  return <div class="prose">{blocks}</div>;
}

export function Assistant({ sha, kind, addr, fnName, autoAsk, full, localOnly, onLocalOnly }: {
  sha: string; kind: 'pdf' | 'native' | 'other' | 'fn'; addr?: string; fnName?: string; autoAsk?: string | null; full?: boolean;
  localOnly?: boolean; onLocalOnly?: (v: boolean) => void;
}) {
  const key = `${sha}:${addr ?? ''}`;
  const [status, setStatus] = useState<AiStatus | null>(null);
  const [statusErr, setStatusErr] = useState<string | null>(null);
  const [turns, setTurns] = useState<ChatTurn[]>(() => chats.get(key) ?? []);
  const [live, setLive] = useState<string | null>(null);
  const [q, setQ] = useState('');
  const [level, setLevel] = useState<Level>(readLevel);
  const [fact, setFact] = useState<{ id: number; text: string | null } | null>(null);
  const [where, setWhere] = useState<string | null>(null);
  const abort = useRef<AbortController | null>(null);
  const asked = useRef(false);
  const latest = useRef('');
  const endRef = useRef<HTMLDivElement>(null);

  const load = (refresh = false) => {
    setStatusErr(null);
    aiStatus(refresh).then(setStatus, (e: Error) => setStatusErr(e.message));
  };
  useEffect(() => { load(); return () => abort.current?.abort(); }, []);
  useEffect(() => { chats.set(key, turns); }, [key, turns]);
  useEffect(() => {
    if (autoAsk && status?.available && !asked.current) { asked.current = true; void ask(autoAsk); }
  }, [status, autoAsk]);
  useEffect(() => { if (live !== null) endRef.current?.scrollIntoView({ block: 'nearest' }); }, [live]);

  const pickLevel = (l: Level) => {
    setLevel(l);
    try { localStorage.setItem('drishti-ai-level', l); } catch { /* ignore */ }
  };
  const cite: Cite = (id) => {
    setFact({ id, text: null });
    api.aiFacts(sha, addr ?? null).then((r) => setFact({ id, text: r.facts[id - 1] ?? 'This fact is no longer available (the analysis changed since the answer).' }), () => setFact({ id, text: 'Could not load the facts.' }));
  };

  const ask = async (question: string) => {
    const text = question.trim();
    if (!text || live !== null) return;
    const history = turns;
    setTurns([...history, { role: 'user', content: text }]);
    setQ('');
    setLive('');
    setFact(null);
    latest.current = '';
    const ac = new AbortController();
    abort.current = ac;
    let answer = '';
    try {
      answer = await api.ask(sha, text, history, addr ?? null, (all) => { latest.current = all; setLive(shown(all)); }, ac.signal, level, (m) => setWhere(m.where));
    } catch (e) {
      if ((e as Error).name !== 'AbortError') {
        notify((e as Error).message, 'error', undefined, 8000);
        setTurns(history);
        setQ(text);
        setLive(null);
        load(true);
        return;
      }
      answer = latest.current;
    } finally {
      abort.current = null;
    }
    // Split the answer into prose + structured claims (old answers have none).
    const raw = visible(answer);
    let turn: ChatTurn = { role: 'assistant', content: shown(raw) || '(no answer)' };
    if (raw) {
      try {
        const p = await api.aiClaims(sha, raw);
        turn = { role: 'assistant', content: p.prose || turn.content, claims: p.claims.length ? p.claims : undefined };
      } catch { /* keep the locally cleaned text */ }
    }
    setTurns((t) => [...t, turn]);
    setLive(null);
  };
  const stop = () => abort.current?.abort();

  const cloud = status?.mode === 'cloud' && !localOnly;
  const badge = status?.available && (
    <span class={`ai-badge${cloud || where === 'cloud' || where === 'remote' ? ' remote' : ''}`} title={cloud ? `Your question and a summary of the file go to ${status.cloud_name}. The file itself is not uploaded.` : 'The model runs on this computer. Nothing is uploaded.'}>
      <Icon name={cloud ? 'cloud' : 'lock'} size={12} /> {cloud ? `${status.cloud_name} · ${status.active_model}` : `Private · ${status.mode === 'cloud' ? status.model ?? 'local model' : status.active_model}`}
    </span>
  );
  const head = (
    <div class="ai-head">
      <h3>{kind === 'fn' ? `Explain ${fnName ?? 'this function'}` : 'Ask Drishti'}</h3>
      {badge}
    </div>
  );

  if (statusErr || (status && !status.available)) {
    const err = statusErr ?? status?.error ?? '';
    const off = status && !status.enabled;
    const noServer = /reach|connect|timed out/i.test(err);
    return (
      <section class={`card assist${full ? ' full' : ''}`}>
        {head}
        {off ? (
          <p>The AI assistant is turned off. You can turn it on in <a href="#/settings/ai">Settings → AI</a>.</p>
        ) : status?.mode === 'cloud' ? (
          <div class="ai-setup"><p>Cloud AI isn't ready: {err}.</p><a class="btn primary" href="#/settings/ai">Open AI settings</a></div>
        ) : (
          <div class="ai-setup">
            <p>Drishti can explain this file in plain language using a free AI model that runs <b>on your own computer</b>, so nothing is uploaded. It needs a one-time setup:</p>
            <ol>
              {noServer && <li>Install <b>Ollama</b> from <span class="mono">ollama.com</span> and open it.</li>}
              <li>In Terminal, run <code class="copy" title="Click to copy" onClick={() => navigator.clipboard?.writeText('ollama pull qwen3:4b-instruct').then(() => notify('Copied', 'ok', undefined, 1200), () => {})}>ollama pull qwen3:4b-instruct</code> (about 2.5 GB).</li>
              <li>Come back and press <b>Try again</b>.</li>
            </ol>
            <p>Or use a cloud AI (Claude, GPT, Gemini…) with your own key in <a href="#/settings/ai">Settings → AI</a>.</p>
            <p class="muted small">{err}</p>
            <button onClick={() => load(true)}>Try again</button>
          </div>
        )}
      </section>
    );
  }

  const suggestions = SUGGEST[kind] ?? SUGGEST.other;
  return (
    <section class={`card assist${full ? ' full' : ''}`}>
      {head}
      <div class="ai-opts">
        <div class="seg small-seg" role="group" aria-label="How detailed">
          {(['simple', 'normal', 'expert'] as Level[]).map((l) => <button class={level === l ? 'on' : ''} onClick={() => pickLevel(l)}>{l === 'simple' ? 'Very simple' : l === 'normal' ? 'Normal' : 'Technical'}</button>)}
        </div>
        {onLocalOnly && status?.mode === 'cloud' && (
          <label class="check-row small" title="Private files are only ever read by the AI on this computer"><input type="checkbox" checked={Boolean(localOnly)} onChange={(e) => onLocalOnly((e.target as HTMLInputElement).checked)} /> Keep this file private (local AI only)</label>
        )}
      </div>
      {!status && <p class="muted">Connecting to the AI…</p>}
      {status && turns.length === 0 && live === null && (
        <div class="ai-suggest">
          {suggestions.map((s) => <button onClick={() => void ask(s)}>{s}</button>)}
        </div>
      )}
      <div class="ai-chat">
        {turns.map((t) => (t.role === 'user' ? <div class="ai-q">{t.content}</div> : <div class="ai-a"><Prose text={t.content} cite={cite} />{t.claims?.length ? <Claims claims={t.claims} /> : <p class="claim-none muted small">Unverified: this answer made no claims Drishti can check.</p>}</div>))}
        {live !== null && <div class="ai-a">{live ? <Prose text={live} cite={cite} /> : <span class="ai-thinking"><i />Reading the facts…</span>}</div>}
        <div ref={endRef} />
      </div>
      {fact && (
        <div class="fact-pop" role="note">
          <b>Fact {fact.id}</b>
          <button class="x" aria-label="Close" onClick={() => setFact(null)}><Icon name="close" size={14} /></button>
          <p class="mono small">{fact.text ?? 'Loading…'}</p>
          <p class="muted small">Drishti found this in the file. The AI used it for that sentence.</p>
        </div>
      )}
      {status && (
        <form class="ai-ask" onSubmit={(e) => { e.preventDefault(); void ask(q); }}>
          <input value={q} placeholder={turns.length ? 'Ask a follow-up…' : 'Ask anything about this file…'} onInput={(e) => setQ((e.target as HTMLInputElement).value)} aria-label="Question" maxLength={4000} />
          {live !== null ? <button type="button" onClick={stop}>Stop</button> : <button class="primary" type="submit" disabled={!q.trim()}>Ask</button>}
          {turns.length > 0 && live === null && <button type="button" onClick={() => setTurns([])}>Clear</button>}
        </form>
      )}
      <p class="muted small ai-note">Answers are based on what Drishti found in the file and can be wrong. Numbers like <span class="cite static">3</span> link to the fact behind a sentence.</p>
    </section>
  );
}
