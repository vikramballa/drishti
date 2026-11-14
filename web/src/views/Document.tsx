// Document cards (PDF): safety verdict, where it came from, metadata,
// edit history and signatures, links. Also the download-origin card, which
// applies to any file opened in place.
import { DocumentReport, FileOrigin } from '../api';
import { notify } from '../store';

const TOPIC: Record<string, string> = {
  downloaded: 'Download', made_with: 'Software', device: 'Device', author: 'Author', signed: 'Signature',
  dates: 'Dates', edited: 'Edits', scanned: 'Scan', region: 'Region', identity: 'Identity',
};
const CONF = { high: '●●●', medium: '●●○', low: '●○○' } as const;
const RISK = {
  info: { icon: '✓', label: 'Looks safe', cls: 'good' },
  low: { icon: '✓', label: 'Looks safe', cls: 'good' },
  medium: { icon: '!', label: 'Use caution', cls: 'warn' },
  high: { icon: '✕', label: 'Be careful', cls: 'bad' },
} as const;

const copy = (t: string) => navigator.clipboard?.writeText(t).then(() => notify('Copied', 'ok', undefined, 1200), () => {});

/** Shortened URL for display; the full value is in the tooltip and copied on click. */
function Url({ u }: { u: string }) {
  let short = u;
  try {
    const x = new URL(u);
    short = x.host + (x.pathname.length > 40 ? x.pathname.slice(0, 38) + '…' : x.pathname) + (x.search ? '?…' : '');
  } catch { /* not a URL */ }
  return <span class="mono url copy" title={`${u}\n(click to copy — links are not opened from here)`} onClick={() => copy(u)}>{short}</span>;
}

export function OriginCard({ origin, doc }: { origin: FileOrigin | null; doc: DocumentReport | null }) {
  const clues = doc?.clues ?? [];
  if (!origin && clues.length === 0) return null;
  return (
    <section class="card wide origin">
      <h3>Where it came from</h3>
      {origin && (
        <div class="clue">
          <span class="ct">Download</span>
          <div>
            {origin.where_from && origin.where_from.length > 0
              ? <>Downloaded from <Url u={origin.where_from[0]} />{origin.where_from[1] && <> via the page <Url u={origin.where_from[1]} /></>}</>
              : 'Downloaded or received from another app'}
            {origin.downloaded_by && <> using <b>{origin.downloaded_by}</b></>}
            {origin.downloaded_at && <> on {origin.downloaded_at}</>}.
            <div class="muted small">Recorded by macOS when the file arrived on this Mac.</div>
          </div>
          <span class="conf" title="high confidence">{CONF.high}</span>
        </div>
      )}
      {clues.map((c) => (
        <div class="clue">
          <span class="ct">{TOPIC[c.topic] ?? c.topic}</span>
          <div>{c.text}</div>
          <span class="conf" title={`${c.confidence} confidence`}>{CONF[c.confidence]}</span>
        </div>
      ))}
      {doc && !origin && <p class="muted small">Tip: open a file by its path (not by uploading) to also see the website or app it was downloaded from.</p>}
      <p class="muted small">●●● strong evidence · ●●○ likely · ●○○ a hint. Metadata can be edited by whoever made the file.</p>
    </section>
  );
}

export function DocumentCards({ doc }: { doc: DocumentReport }) {
  const r = RISK[doc.risk];
  const meta = doc.metadata;
  return (
    <>
      <section class={`card safety ${r.cls}`}>
        <h3>Is it safe to open?</h3>
        <div class="verdict"><span class="vi">{r.icon}</span><div><b>{r.label}</b><p>{doc.verdict}</p></div></div>
        {doc.features.map((f) => (
          <div class={`finding sev-${f.severity}`}><span class="sev">{f.severity}</span><div><b>{f.name}</b>{f.count > 1 && <span class="muted"> ×{f.count}</span>}<div class="muted">{f.explanation}</div></div></div>
        ))}
        {doc.embedded_files.length > 0 && <p class="small">Attached files: {doc.embedded_files.map((f) => <span class="tag">{f}</span>)}</p>}
        {doc.warnings?.map((w) => <p class="muted small">{w}</p>)}
        <p class="muted small">Drishti reads the file without opening or running it.</p>
      </section>
      <section class="card">
        <h3>Document</h3>
        <dl>
          {doc.pages != null && <><dt>Pages</dt><dd>{doc.pages}</dd></>}
          {doc.page_size && <><dt>Page size</dt><dd>{doc.page_size}</dd></>}
          {doc.version && <><dt>PDF version</dt><dd>{doc.version}</dd></>}
          <dt>Saved</dt><dd>{doc.revisions === 1 ? 'once' : `${doc.revisions} times`}</dd>
          {doc.encrypted && <><dt>Encrypted</dt><dd>yes</dd></>}
          {doc.images > 0 && <><dt>Images</dt><dd>{doc.images}</dd></>}
          {doc.fonts.length > 0 && <><dt>Fonts</dt><dd>{doc.fonts.slice(0, 8).join(', ')}{doc.fonts.length > 8 ? ` +${doc.fonts.length - 8}` : ''}</dd></>}
        </dl>
      </section>
      {meta.length > 0 && (
        <section class="card">
          <h3>Details inside the file</h3>
          {meta.map((m) => (
            <div class="meta"><span class="mk">{m.key}</span><span class="mv" title={m.value}>{m.value}</span><span class={`src s-${m.source}`} title={SRC[m.source] ?? m.source}>{m.source}</span></div>
          ))}
        </section>
      )}
      {(doc.signatures.length > 0 || doc.history.length > 0) && (
        <section class="card">
          <h3>Signatures & history</h3>
          {doc.signatures.map((s) => (
            <div class={`check st-${s.covers_whole_file ? 'good' : 'bad'}`}>
              <span class="ci">{s.covers_whole_file ? '✓' : '!'}</span>
              <div>
                <b>Signed by {s.signer ?? 'unknown'}</b>
                <div class="muted">
                  {s.signed_at && <>On {s.signed_at}. </>}
                  {s.issuer && <>Certificate issued by {s.issuer}. </>}
                  {s.reason && <>Reason: {s.reason}. </>}
                  {s.location && <>Location: {s.location}. </>}
                  {s.covers_whole_file ? 'Nothing was changed after signing.' : 'The file was changed after this signature.'}
                </div>
                <div class="muted small">Drishti shows who the certificate names; it does not check whether the certificate is trusted.</div>
              </div>
            </div>
          ))}
          {doc.history.map((h) => (
            <div class="kv"><span>{h.action}{h.software ? ` · ${h.software}` : ''}</span><span class="muted">{h.when ?? ''}</span></div>
          ))}
        </section>
      )}
      {doc.links.length > 0 && (
        <section class="card">
          <h3>Links in the document ({doc.links.length})</h3>
          <div class="ioclist">{doc.links.map((l) => <Url u={l} />)}</div>
          <p class="muted small">Click to copy. Check where a link really goes before visiting it.</p>
        </section>
      )}
    </>
  );
}

const SRC: Record<string, string> = {
  info: 'Document information dictionary',
  xmp: 'XMP metadata packet',
  trailer: 'File trailer (IDs)',
  catalog: 'Document catalog',
  previous: 'An older saved version of the file',
};
