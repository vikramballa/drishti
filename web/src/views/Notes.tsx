// User annotations (renames, comments) for this binary.
import { api } from '../api';
import { useAsync } from '../components/hooks';
import { dataVersion, goAddr, refreshData, route } from '../store';

export function Notes() {
  const sha = route.value.sha!;
  const a = useAsync(() => api.annotations(sha), [sha, dataVersion.value]);
  return (
    <div class="notes">
      <div class="code-head"><h2>Notes</h2><span class="muted">Renames and comments you have made</span></div>
      {a.data?.items.length === 0 && <div class="empty">No annotations yet. Use Rename / Comment in the code view.</div>}
      {a.data?.items.map((n) => (
        <div class="note">
          <a class="mono" onClick={() => goAddr(n.addr)}>{n.addr}</a>
          <span class="chip">{n.kind.replace('_', ' ')}</span>
          <span class="nval">{n.value}</span>
          <button aria-label="Delete note" onClick={async () => { await api.deleteAnnotation(sha, n.id); refreshData(sha); }}>×</button>
        </div>
      ))}
    </div>
  );
}
