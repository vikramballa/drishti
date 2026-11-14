// Ask: the assistant as a full page, with suggested questions per file type.
import { useState } from 'preact/hooks';
import { api, NATIVE } from '../api';
import { Assistant } from '../components/Assistant';
import { useAsync } from '../components/hooks';
import { binary, notify, pendingAsk, route } from '../store';

export function Ask() {
  const sha = route.value.sha!;
  const b = binary.value;
  const ins = useAsync(() => api.insights(sha), [sha]);
  const [priv, setPriv] = useState<boolean | null>(null);
  const [first] = useState(() => { const q = pendingAsk.value; pendingAsk.value = null; return q; });
  const fmt = b?.file.format ?? '';
  const kind = fmt === 'pdf' ? 'pdf' : NATIVE.includes(fmt) ? 'native' : 'other';
  const localOnly = priv ?? ins.data?.local_only ?? false;
  const setLocalOnly = async (v: boolean) => {
    try { await api.saveSettings({ [`file.local_only.${sha}`]: v }); setPriv(v); notify(v ? 'This file will only be read by the AI on this computer.' : 'Cloud AI may read facts about this file.', 'ok'); }
    catch (e) { notify((e as Error).message, 'error'); }
  };
  return (
    <div class="page ask-page">
      <header class="page-head"><div><h1>Ask Drishti</h1><p class="muted">Ask in your own words. Answers use only what Drishti found in this file.</p></div></header>
      <Assistant key={sha} sha={sha} kind={kind} autoAsk={first} full localOnly={localOnly} onLocalOnly={(v) => void setLocalOnly(v)} />
    </div>
  );
}
