// A short first-run introduction (4 steps). Shown once; Settings → General
// can show it again.
import { useState } from 'preact/hooks';
import { Icon } from './Icon';

const STEPS: { icon: string; title: string; body: string }[] = [
  { icon: 'good', title: 'Welcome to Drishti', body: 'Drishti looks inside programs, apps and documents and tells you, in plain words, what they are and whether they look safe. It only reads files. Nothing you open is ever run.' },
  { icon: 'upload', title: 'Open something', body: 'Drop a file on the home screen, pick an installed app, or check your whole Mac: what starts automatically and who made each app.' },
  { icon: 'summary', title: 'Read the summary', body: 'Every file starts with a verdict (green, amber or red) and the reasons for it, then who made it, what it can access and who it talks to. Words with a dotted underline explain themselves when you point at them.' },
  { icon: 'ask', title: 'Ask, check, dig deeper', body: 'Ask questions in your own words, run free safety scans, and switch to Expert mode (top right) when you want to see the code itself.' },
];

export function Tour() {
  const [open, setOpen] = useState(() => { try { return !localStorage.getItem('drishti-tour'); } catch { return false; } });
  const [i, setI] = useState(0);
  if (!open) return null;
  const done = () => { try { localStorage.setItem('drishti-tour', '1'); } catch { /* ignore */ } setOpen(false); };
  const s = STEPS[i];
  return (
    <div class="sheet center tour-wrap" role="dialog" aria-modal="true" aria-label="Introduction">
      <div class="tour">
        <div class="tour-ic"><Icon name={s.icon} size={28} /></div>
        <h2>{s.title}</h2>
        <p>{s.body}</p>
        <div class="tour-dots">{STEPS.map((_, k) => <span class={k === i ? 'on' : ''} />)}</div>
        <div class="tour-actions">
          <button class="link" onClick={done}>Skip</button>
          {i > 0 && <button onClick={() => setI(i - 1)}>Back</button>}
          {i < STEPS.length - 1 ? <button class="primary" onClick={() => setI(i + 1)}>Next</button> : <button class="primary" onClick={done}>Start</button>}
        </div>
      </div>
    </div>
  );
}
