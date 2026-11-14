// Typed client for the Drishti API (/api/v1). All data access goes through
// here; responses are cached per URL and invalidated per binary.

export type Addr = string;

export interface FileInfo {
  sha256: string; md5: string; size: number; file_name: string; format: string;
  container?: string | null; arch: string; bits: number | null; endian: string | null;
  platform: string; entry_point?: Addr; is_stripped?: boolean; is_packed_suspected?: boolean;
  entropy: number; compiler_hints?: string[]; libraries?: string[];
  children?: { path: string; sha256: string; format: string; size: number; arch?: string }[];
}
export interface Section { name: string; vaddr: Addr; vsize: number; file_offset: number; file_size: number; perms: string; entropy: number }
export interface Finding { kind: string; severity: 'info' | 'low' | 'medium' | 'high'; title: string; detail: string; source: string; addrs?: Addr[] }
export interface Job { id: string; sha256: string; status: string; phase?: string; functions: number; instructions: number; error?: string }
export interface BinaryDetail {
  file: FileInfo; sections: Section[] | null; findings: Finding[];
  counts: { imports: number | null; exports: number | null; symbols: number | null; strings: number };
  image_base: Addr | null; analysed: boolean; job: Job | null; warnings: string[] | null; load_error: string | null;
  analysis: { functions: number; instructions: number; xrefs: number; jump_tables: number; gap_functions: number; duration_ms: number } | null;
  watched: boolean;
}
export interface FnRow { entry: Addr; name: string; renamed: boolean; size: number; blocks: number; insns: number; calls: number; callers: number; cyclomatic: number; thunk: boolean; noreturn: boolean }
export interface Insn { addr: Addr; size: number; bytes: string; mnemonic: string; operands: string; kind: string; targets?: Addr[]; comment?: string }
export interface Block { start: Addr; end: Addr; successors: { target: Addr; kind: string }[]; instructions: Insn[] }
export interface Ref { addr: Addr; name: string | null }
export interface FunctionDetail {
  entry: Addr; name: string; original_name: string; size: number; insns: number; is_thunk: boolean; noreturn: boolean;
  metrics: { block_count: number; edge_count: number; cyclomatic: number }; blocks: Block[]; truncated: boolean;
  callees: Ref[]; callers: Ref[]; xrefs_to: { from: Addr; to: Addr; kind: string }[]; strings: { from: Addr; addr: Addr; value: string }[];
}
export interface Page<T> { total: number; offset: number; items: T[] }
export interface Sym { name: string; demangled?: string; addr: Addr; size?: number; kind: string; library?: string; source: string; capability?: string | null }
export interface Str { addr: Addr; value: string; encoding: string; xrefs: Addr[] }
export interface XrefItem { from: Addr; to: Addr; kind: string; function: { entry: Addr; name: string } | null; target_name: string | null }
export interface Annotation { id: string; addr: Addr; kind: string; value: string; author: string; ai_status?: string | null; updated_at: string }
export interface Check { name: string; status: 'good' | 'bad' | 'info'; detail: string }
export interface Behavior { name: string; category: string; severity: string; description: string; apis: string[]; functions: { entry: Addr; name: string }[]; function_count: number }
export type Severity = 'info' | 'low' | 'medium' | 'high';
export interface DocumentReport {
  kind: string; version?: string; pages?: number; page_size?: string; encrypted: boolean; linearized: boolean; revisions: number;
  metadata: { key: string; value: string; source: string }[];
  history: { when?: string; action: string; software?: string }[];
  signatures: { signer?: string; issuer?: string; signed_at?: string; reason?: string; location?: string; certificate_names?: string[]; covers_whole_file: boolean }[];
  fonts: string[]; images: number; links: string[]; embedded_files: string[];
  features: { name: string; count: number; severity: Severity; explanation: string }[];
  clues: { topic: string; text: string; confidence: 'low' | 'medium' | 'high' }[];
  risk: Severity; verdict: string; warnings?: string[];
}
export interface FileOrigin { where_from?: string[]; downloaded_by?: string; downloaded_at?: string; quarantined: boolean }
export type Tone = 'bad' | 'warn' | 'good' | 'info';
export interface Permission { id: string; label: string; icon: string; sensitive: boolean; why: string[]; explanation: string | null }
export interface Sdk { name: string; category: string; category_label: string; evidence: string[] }
export interface Plain {
  verdict: { level: 'good' | 'caution' | 'danger' | 'unknown'; title: string; reasons: { tone: Tone; text: string }[]; scanned: boolean };
  maker: { name: string | null; trust: string; detail: string[]; app: { name: string | null; id: string | null; version: string | null; min_os: string | null; copyright: string | null; root: string; electron: boolean; frameworks: number; background_only: boolean } | null };
  permissions: Permission[];
  network: { groups: { id: string; label: string; hosts: string[] }[]; ips: string[]; contacted: number };
  sdks: Sdk[];
  grades: { security: string | null; privacy: string | null; trust: string | null };
}
export interface Bundle { root: string; name: string | null; bundle_id: string | null; version: string | null; frameworks: string[]; helpers: string[]; asar: string | null; usage: [string, string][] }
export interface Insights {
  summary: string; hardening: Check[];
  signing: { signed: boolean; adhoc: boolean; identifier: string | null; team_id: string | null; hardened_runtime: boolean; entitlements: [string, string][] } | null;
  behaviors: Behavior[]; iocs: { kind: string; value: string; addr: Addr }[];
  document: DocumentReport | null; origin: FileOrigin | null;
  plain: Plain; bundle: Bundle | null; local_only: boolean;
}
export interface CloudInfo { id: string; name: string; key_set: boolean; suggested: string[]; model: string | null }
export interface AiStatus {
  enabled: boolean; available: boolean; url: string; provider: string; model: string | null; models: string[];
  cloud_models: string[]; local: boolean; url_editable: boolean; error: string | null;
  mode: 'local' | 'cloud'; cloud_provider: string | null; cloud_name: string | null; cloud_consent: boolean; clouds: CloudInfo[];
  active_model: string | null; local_available: boolean;
}
export type Verdict = 'clean' | 'warning' | 'danger' | 'info' | 'unknown' | 'error';
export interface ToolItem { title: string; detail: string; severity: Severity; [k: string]: unknown }
export interface ToolResult { verdict: Verdict; headline: string; items: ToolItem[]; data?: Record<string, unknown>; duration_ms?: number; version?: string; finished_at?: string; tool?: string }
export interface SetupState { id: string; ready: boolean; label: string; action: string; note: string; version?: string; age_days?: number | null }
export interface ToolInfo {
  id: string; name: string; what: string; kind: 'decompiler' | 'safety' | 'details' | 'apps'; installed: boolean; path: string | null; version: string | null;
  install: string; homepage: string; license: string; heavy: boolean; auto: boolean; setup: SetupState | null; java_ok: boolean; extra: Record<string, unknown> | null;
}
export interface FileTool { id: string; name: string; what: string; kind: string; installed: boolean; install: string; heavy: boolean; setup: SetupState | null; status: 'idle' | 'queued' | 'running' | 'done' | 'failed'; error: string | null; result: ToolResult | null }
export interface Decompiled { status: 'done' | 'queued' | 'running' | 'failed' | 'missing'; engine: string; code?: string; name?: string; signature?: string; message?: string | null; install?: string; first_time?: boolean; elapsed_s?: number; duration_ms?: number; quality?: string }
export interface LookupService { id: string; name: string; sends: string; what: string; key_set: boolean; key_id: string; result: (ToolResult & Record<string, unknown> & { checked_at?: string }) | null }
export interface SecretKey { id: string; label: string; env: string; get_url: string; set: boolean; source: 'environment' | 'saved' | 'none'; hint: string | null }
export interface StartupItem { file: string; label: string | null; when: string; program: string | null; args: string[]; app: string | null; run_at_load: boolean; keep_alive: boolean; disabled: boolean; signer: { kind: string; developer?: string | null; team?: string | null; notarized?: boolean }; level: string; note: string }
export interface AppScan { name: string; path: string; exe: string | null; id: string | null; version: string | null; signer: StartupItem['signer']; level: string; note: string; access: string[]; kits: string[]; electron: boolean; login_items: number }
export interface ChatTurn { role: 'user' | 'assistant'; content: string }

/** Formats that contain machine code the core engine analyses. */
export const NATIVE = ['elf', 'pe', 'pe-dotnet', 'macho', 'macho-fat', 'coff'];
export type SearchMode = 'text' | 'hex' | 'regex' | 'number' | 'insn';
export interface SearchOpts {
  mode: SearchMode; q: string; case?: boolean; enc?: string; width?: string; endian?: string;
  scope?: string; regex?: boolean; fn?: string;
}
export interface SearchHit {
  offset?: number; len?: number; va: Addr | null; section?: string | null; function: { entry: Addr; name: string } | null;
  label: string; bytes?: string; text?: string; before?: string; after?: string; lines?: string[];
}
export interface SearchResult {
  mode: SearchMode; total: number; capped: boolean; partial: boolean; offset: number; hits: SearchHit[]; elapsed_ms: number;
  by_kind?: Record<string, number>; searched_bytes?: number; functions_scanned?: number; functions_total?: number; instructions_scanned?: number;
}
export interface SearchAllResult {
  files: { sha256: string; file_name: string; size: number; total: number; capped: boolean; hits: SearchHit[] }[];
  searched: number; unreadable: number; searched_bytes: number; partial: boolean; elapsed_ms: number;
}
export interface DiffFn { name: string; old: Addr | null; new: Addr | null; old_size: number; new_size: number }
export interface DiffResult { diff: { unchanged: number; changed: DiffFn[]; added: DiffFn[]; removed: DiffFn[]; truncated: boolean }; old_name: string; old_functions: number; new_functions: number }
export interface ResolveHit { kind: string; addr: Addr; label: string }

const BASE = '/api/v1';
const cache = new Map<string, Promise<unknown>>();

function token(): string | null {
  try { return localStorage.getItem('drishti-token'); } catch { return null; }
}

export class ApiError extends Error {
  constructor(public status: number, message: string) { super(message); }
}

export interface VulnFnRef { entry: Addr; name: string }
export interface VulnFinding {
  class: string;
  title: string;
  severity: 'high' | 'medium' | 'low' | 'info';
  confidence: 'high' | 'medium' | 'low';
  sink_api: string;
  sink_fn: VulnFnRef;
  source_api?: string;
  source_fn?: VulnFnRef;
  path: VulnFnRef[];
  explanation: string;
}
export interface VulnReport {
  findings: VulnFinding[];
  scanned_functions: number;
  sources_found: number;
  sinks_found: number;
  note: string;
}
export interface NlResult {
  question: string;
  query: string;
  notes: string[];
  source: string;
  understood: boolean;
  hint?: string;
  matches: { entry: Addr; name: string; size: number | null; callers: number; complexity: number }[];
  total: number;
}

async function req<T>(path: string, init?: RequestInit): Promise<T> {
  const headers: Record<string, string> = { ...(init?.headers as Record<string, string> | undefined) };
  const t = token();
  if (t) headers.Authorization = `Bearer ${t}`;
  const r = await fetch(BASE + path, { ...init, headers });
  if (!r.ok) {
    let msg = r.statusText;
    try { msg = (await r.json()).error ?? msg; } catch { /* not json */ }
    throw new ApiError(r.status, msg);
  }
  return r.json() as Promise<T>;
}

/** Cached GET. Failed requests are evicted so they can be retried. */
export function get<T>(path: string): Promise<T> {
  let p = cache.get(path) as Promise<T> | undefined;
  if (!p) {
    p = req<T>(path);
    cache.set(path, p);
    p.catch(() => cache.delete(path));
  }
  return p;
}

export function invalidate(sha?: string) {
  for (const k of [...cache.keys()]) if (!sha || k.includes(sha)) cache.delete(k);
}

const q = (o: Record<string, string | number | boolean | undefined | null>) =>
  Object.entries(o).filter(([, v]) => v !== undefined && v !== null && v !== '' && v !== false).map(([k, v]) => `${k}=${encodeURIComponent(v === true ? '1' : String(v))}`).join('&');

export const api = {
  binaries: () => req<{ binaries: { sha256: string; file_name: string; size: number; format: string; ext_path: string | null; created_at: string }[] }>('/binaries'),
  binary: (sha: string) => req<BinaryDetail>(`/binaries/${sha}`),
  upload: (file: File) =>
    req<{ binary_id: string; job_id: string | null }>(`/binaries?${q({ name: file.name })}`, { method: 'POST', body: file, headers: { 'content-type': 'application/octet-stream' } }),
  openPath: (path: string) => req<{ binary_id: string; job_id: string | null }>('/binaries/open', { method: 'POST', body: JSON.stringify({ path }), headers: { 'content-type': 'application/json' } }),
  analyze: (sha: string) => req<{ job_id: string }>('/jobs', { method: 'POST', body: JSON.stringify({ binary: sha, engines: ['core'] }), headers: { 'content-type': 'application/json' } }),
  functions: (sha: string, filter: string, sort: string, offset = 0, limit = 5000) => get<Page<FnRow>>(`/binaries/${sha}/functions?${q({ filter, sort, offset, limit })}`),
  fn: (sha: string, addr: Addr) => get<FunctionDetail>(`/binaries/${sha}/functions/${addr}`),
  disasm: (sha: string, addr: Addr, count = 300) => get<{ addr: Addr; instructions: Insn[]; labels: Record<string, string>; section: string | null; function: { entry: Addr; name: string } | null }>(`/binaries/${sha}/disasm?${q({ addr, count })}`),
  table: (sha: string, which: 'imports' | 'exports' | 'symbols', filter = '', offset = 0, limit = 20000) => get<Page<Sym>>(`/binaries/${sha}/${which}?${q({ filter, offset, limit })}`),
  strings: (sha: string, filter = '', offset = 0, limit = 2000, opts: { enc?: string; min?: number; refs?: boolean } = {}) =>
    get<Page<Str>>(`/binaries/${sha}/strings?${q({ filter, offset, limit, enc: opts.enc, min: opts.min || undefined, refs: opts.refs ? 1 : undefined })}`),
  xrefsTo: (sha: string, addr: Addr) => get<{ items: XrefItem[] }>(`/binaries/${sha}/xrefs?to=${addr}`),
  callgraph: (sha: string, root: Addr, depth: number) => get<{ nodes: { addr: Addr; name: string; import: boolean; root: boolean }[]; edges: { from: Addr; to: Addr }[] }>(`/binaries/${sha}/callgraph?${q({ root, depth })}`),
  resolve: (sha: string, query: string) => req<{ results: ResolveHit[] }>(`/binaries/${sha}/resolve?${q({ q: query })}`),
  annotations: (sha: string) => req<{ items: Annotation[] }>(`/binaries/${sha}/annotations`),
  annotate: (sha: string, addr: Addr, kind: string, value: string) =>
    req<Annotation>(`/binaries/${sha}/annotations`, { method: 'POST', body: JSON.stringify({ addr, kind, value }), headers: { 'content-type': 'application/json' } }),
  deleteAnnotation: (sha: string, id: string) => req<unknown>(`/binaries/${sha}/annotations/${id}`, { method: 'DELETE' }),
  insights: (sha: string) => get<Insights>(`/binaries/${sha}/insights`),
  vulns: (sha: string) => get<VulnReport>(`/binaries/${sha}/vulns`),
  nlQuery: (sha: string, question: string) => req<NlResult>(`/binaries/${sha}/nl-query`, { method: 'POST', body: JSON.stringify({ question }), headers: { 'content-type': 'application/json' } }),
  search: (sha: string, o: SearchOpts, offset = 0, limit = 200) => req<SearchResult>(`/binaries/${sha}/search?${q({ ...o, offset, limit })}`),
  searchAll: (o: SearchOpts, limit = 5) => req<SearchAllResult>(`/search?${q({ ...o, limit })}`),
  diff: (sha: string, other: string) => req<DiffResult>(`/binaries/${sha}/diff?${q({ other })}`),
  apps: () => req<{ apps: { name: string; path: string }[] }>('/local/apps'),
  reportUrl: (sha: string) => `${BASE}/binaries/${sha}/report.md${token() ? `?token=${encodeURIComponent(token()!)}` : ''}`,
  settings: () => req<Record<string, unknown>>('/settings'),
  saveSettings: (v: Record<string, unknown>) => req<unknown>('/settings', { method: 'PUT', body: JSON.stringify(v), headers: { 'content-type': 'application/json' } }),
  aiStatus: () => req<AiStatus>('/ai/status'),
  aiFacts: (sha: string, addr: Addr | null) => get<{ facts: string[] }>(`/binaries/${sha}/ai/facts?${q({ addr })}`),
  cloudModels: (id: string) => req<{ models: string[]; suggested: string[] }>(`/ai/cloud/${id}/models`),
  secrets: () => req<{ keys: SecretKey[] }>('/secrets'),
  setSecret: (id: string, value: string) => req<{ keys: SecretKey[] }>(`/secrets/${id}`, { method: 'PUT', body: JSON.stringify({ value }), headers: { 'content-type': 'application/json' } }),
  deleteSecret: (id: string) => req<{ keys: SecretKey[] }>(`/secrets/${id}`, { method: 'DELETE' }),
  tools: () => req<{ tools: ToolInfo[]; sandbox: boolean; allow_unsandboxed: boolean; online: boolean; tasks: Record<string, { status: string; error: string | null }> }>('/tools'),
  setupTool: (id: string) => req<{ key: string; started: boolean }>(`/tools/${id}/setup`, { method: 'POST' }),
  fileTools: (sha: string) => req<{ tools: FileTool[] }>(`/binaries/${sha}/tools`),
  runTool: (sha: string, id: string) => req<{ started: boolean }>(`/binaries/${sha}/tools/${id}`, { method: 'POST' }),
  decompile: (sha: string, addr: Addr, engine?: string) => req<Decompiled>(`/binaries/${sha}/decompile?${q({ addr, engine })}`),
  sourceList: (sha: string, tool: string) => req<{ files: [string, number][]; truncated: boolean }>(`/binaries/${sha}/source?${q({ tool })}`),
  sourceFile: (sha: string, tool: string, path: string) => req<{ path: string; size: number; truncated: boolean; text: string }>(`/binaries/${sha}/source?${q({ tool, path })}`),
  lookups: (sha: string) => req<{ enabled: boolean; online: boolean; services: LookupService[] }>(`/binaries/${sha}/lookups`),
  runLookup: (sha: string, id: string) => req<ToolResult & Record<string, unknown>>(`/binaries/${sha}/lookups/${id}`, { method: 'POST' }),
  trust: (sha: string) => req<{ available: boolean; signed?: boolean; valid?: boolean | null; error?: string | null; reason?: string }>(`/binaries/${sha}/trust`),
  startup: () => req<{ items: StartupItem[] }>('/local/startup'),
  scanApps: () => req<{ apps: AppScan[]; scanned_at: string }>('/local/scan-apps'),
  /** Ask the AI about a file (or one function); streams the answer. */
  async ask(sha: string, question: string, history: ChatTurn[], addr: Addr | null, onText: (all: string) => void, signal: AbortSignal, level?: string, onMeta?: (m: { model: string | null; where: string | null }) => void): Promise<string> {
    const t = token();
    const headers: Record<string, string> = { 'content-type': 'application/json' };
    if (t) headers.Authorization = `Bearer ${t}`;
    const r = await fetch(`${BASE}/binaries/${sha}/ai/ask`, { method: 'POST', headers, body: JSON.stringify({ question, history, addr, level }), signal });
    onMeta?.({ model: r.headers.get('x-ai-model'), where: r.headers.get('x-ai-where') });
    if (!r.ok || !r.body) {
      let msg = r.statusText;
      try { msg = (await r.json()).error ?? msg; } catch { /* not json */ }
      throw new ApiError(r.status, msg);
    }
    const reader = r.body.getReader();
    const dec = new TextDecoder();
    let all = '';
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      all += dec.decode(value, { stream: true });
      onText(all);
    }
    return all;
  },
  async bytes(sha: string, offset: number, len: number): Promise<{ offset: number; size: number; data: Uint8Array }> {
    const t = token();
    const r = await fetch(`${BASE}/binaries/${sha}/bytes?${q({ offset, len })}`, { headers: t ? { Authorization: `Bearer ${t}` } : {} });
    if (!r.ok) throw new ApiError(r.status, r.statusText);
    return { offset: Number(r.headers.get('x-offset') ?? offset), size: Number(r.headers.get('x-file-size') ?? 0), data: new Uint8Array(await r.arrayBuffer()) };
  },
  async vaToOffset(sha: string, va: Addr): Promise<number | null> {
    const t = token();
    const r = await fetch(`${BASE}/binaries/${sha}/bytes?${q({ va, len: 1 })}`, { headers: t ? { Authorization: `Bearer ${t}` } : {} });
    return r.ok ? Number(r.headers.get('x-offset')) : null;
  },
};

export interface ServerEvent { type: string; job_id?: string | null; sha256?: string | null; status?: string | null; phase?: string | null; functions?: number | null; instructions?: number | null; message?: string | null; job?: Job }

/** Live event stream with automatic reconnect. */
export function connectEvents(on: (e: ServerEvent) => void): () => void {
  let ws: WebSocket | null = null;
  let stop = false;
  let delay = 500;
  const open = () => {
    const proto = location.protocol === 'https:' ? 'wss' : 'ws';
    const t = token();
    ws = new WebSocket(`${proto}://${location.host}${BASE}/events${t ? `?token=${encodeURIComponent(t)}` : ''}`);
    ws.onopen = () => { delay = 500; };
    ws.onmessage = (m) => { try { on(JSON.parse(m.data)); } catch { /* ignore */ } };
    ws.onclose = () => { if (!stop) setTimeout(open, delay = Math.min(delay * 2, 8000)); };
  };
  open();
  return () => { stop = true; ws?.close(); };
}

export const hex = (n: number | bigint) => '0x' + n.toString(16);
export const toBig = (a: Addr) => BigInt(a);
export const fmtSize = (n: number) => n < 1024 ? `${n} B` : n < 1 << 20 ? `${(n / 1024).toFixed(1)} KB` : n < 1 << 30 ? `${(n / (1 << 20)).toFixed(1)} MB` : `${(n / (1 << 30)).toFixed(2)} GB`;
