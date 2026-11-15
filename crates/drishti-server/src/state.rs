//! Shared server state: database, open-binary sessions (LRU), jobs, events.

use drishti_disasm::Analysis;
use drishti_loader::{Blob, Image};
use drishti_model::{Addr, AnnotationKind, FileInfo, Finding, StringRef};
use rusqlite::{Connection, OptionalExtension, params};
use serde::Serialize;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
use tokio::sync::{Semaphore, broadcast};

/// Max analysed binaries kept in memory. Each holds an mmap (page cache,
/// reclaimable) plus compact analysis tables.
const MAX_SESSIONS: usize = 3;

/// One opened binary. Immutable once built; a finished analysis produces
/// a new `Session` that replaces the old one in the cache.
pub struct Session {
    pub sha: String,
    pub blob: Arc<Blob>,
    pub image: Option<Arc<Image>>,
    pub info: FileInfo,
    pub findings: Vec<Finding>,
    /// Sorted by address.
    pub strings: Arc<Vec<StringRef>>,
    pub analysis: Option<Analysis>,
    pub load_error: Option<String>,
}

impl Session {
    /// Display name for `addr` (no annotations): function, symbol, import,
    /// or a short string preview.
    pub fn base_name(&self, addr: u64) -> Option<String> {
        if let Some(a) = &self.analysis
            && let Some(f) = a.function_at(addr)
        {
            return Some(f.name.to_string());
        }
        if let Some(img) = &self.image {
            if let Some(s) = img.import_at(addr) {
                return Some(s.display_name().to_string());
            }
            if let Ok(i) = img.symbols.binary_search_by_key(&Addr(addr), |s| s.addr) {
                return Some(img.symbols[i].display_name().to_string());
            }
        }
        if let Ok(i) = self.strings.binary_search_by_key(&Addr(addr), |s| s.addr) {
            let v = &self.strings[i].value;
            let mut p: String = v.chars().take(48).collect();
            if v.chars().count() > 48 {
                p.push('…');
            }
            return Some(format!("{p:?}"));
        }
        None
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Event {
    #[serde(rename = "type")]
    pub kind: &'static str,
    pub job_id: Option<String>,
    pub sha256: Option<String>,
    pub status: Option<String>,
    pub phase: Option<String>,
    pub functions: Option<u64>,
    pub instructions: Option<u64>,
    pub message: Option<String>,
}

impl Event {
    pub fn job(job_id: &str, sha: &str, status: &str) -> Event {
        Event {
            kind: "job",
            job_id: Some(job_id.into()),
            sha256: Some(sha.into()),
            status: Some(status.into()),
            phase: None,
            functions: None,
            instructions: None,
            message: None,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct JobInfo {
    pub id: String,
    pub sha256: String,
    pub engines: Vec<String>,
    pub status: String,
    pub phase: Option<String>,
    pub functions: u64,
    pub instructions: u64,
    pub error: Option<String>,
    pub created_at: String,
    pub finished_at: Option<String>,
    #[serde(skip)]
    pub cancel: Arc<AtomicBool>,
}

pub struct AppState {
    pub data_dir: PathBuf,
    pub local_mode: bool,
    pub token: Option<String>,
    pub upload_limit: u64,
    pub db: Mutex<Connection>,
    pub sessions: Mutex<Vec<Arc<Session>>>,
    /// Per-binary load locks: concurrent requests for a binary that is not
    /// in memory wait for one load instead of each loading (and holding) a
    /// full copy of the image and analysis.
    pub session_loads: Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
    pub jobs: Mutex<HashMap<String, JobInfo>>,
    pub events: broadcast::Sender<Event>,
    /// Limits concurrent analyses (CPU + memory bound).
    pub analysis_slots: Semaphore,
    /// sha → (path, mtime) for binaries analysed in place; watched for changes.
    pub watched: Mutex<HashMap<String, (PathBuf, i64)>>,
    /// Lifted functions (IR), keyed by (first 8 bytes of the sha, entry);
    /// capped by bytes of IR (`DRISHTI_LIFT_CACHE_MB`, default 64). Empty
    /// until someone asks for a function's IR.
    pub lift_cache: Mutex<drishti_disasm::lift::LiftCache<(u64, u64)>>,
}

pub type Shared = Arc<AppState>;

/// Byte budget of [`AppState::lift_cache`].
pub fn lift_cache_bytes() -> usize {
    std::env::var("DRISHTI_LIFT_CACHE_MB")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(64)
        .clamp(1, 4096)
        << 20
}

/// Total size of persisted analyses kept in `data/cache` (LRU by mtime).
const CACHE_MAX_BYTES: u64 = 2 << 30;

impl AppState {
    /// Where the core analysis of `sha` (default options) is persisted.
    pub fn analysis_cache_path(&self, sha: &str) -> PathBuf {
        let key = drishti_disasm::cache::cache_key(sha, &drishti_disasm::Options::default());
        self.data_dir.join("cache").join(format!("{key}.bin"))
    }

    /// Persist an analysis (blocking; call from the blocking pool).
    pub fn store_analysis(&self, sha: &str, a: &Analysis) {
        let path = self.analysis_cache_path(sha);
        match drishti_disasm::cache::store(&path, a) {
            Ok(()) => {
                if let Some(dir) = path.parent() {
                    drishti_disasm::cache::prune(dir, CACHE_MAX_BYTES);
                }
            }
            Err(e) => tracing::warn!("could not persist analysis for {sha}: {e}"),
        }
    }

    pub fn blob_path(&self, sha: &str) -> PathBuf {
        let pre = sha.get(..2).unwrap_or("00");
        self.data_dir.join("blobs").join(pre).join(sha)
    }

    pub fn emit(&self, e: Event) {
        let _ = self.events.send(e);
    }

    pub fn cached(&self, sha: &str) -> Option<Arc<Session>> {
        let mut s = self.sessions.lock().ok()?;
        let i = s.iter().position(|x| x.sha == sha)?;
        let v = s.remove(i);
        s.insert(0, v.clone());
        Some(v)
    }

    pub fn put_session(&self, sess: Arc<Session>) {
        if let Ok(mut s) = self.sessions.lock() {
            s.retain(|x| x.sha != sess.sha);
            s.insert(0, sess);
            s.truncate(MAX_SESSIONS);
        }
    }

    /// Resolve where a binary's bytes live (store or in-place path).
    pub fn binary_location(&self, sha: &str) -> Option<PathBuf> {
        let db = self.db.lock().ok()?;
        let ext: Option<Option<String>> = db
            .query_row(
                "SELECT ext_path FROM binaries WHERE sha256 = ?1",
                params![sha],
                |r| r.get(0),
            )
            .optional()
            .ok()?;
        match ext? {
            Some(p) => Some(PathBuf::from(p)),
            None => Some(self.blob_path(sha)),
        }
    }

    /// Function-name overrides from annotations.
    pub fn renames(&self, sha: &str) -> HashMap<u64, String> {
        let mut out = HashMap::new();
        let Ok(db) = self.db.lock() else { return out };
        let Ok(mut st) = db.prepare_cached("SELECT addr, value FROM annotations WHERE sha256 = ?1 AND kind = 'rename_function' AND (ai_status IS NULL OR ai_status = 'accepted' OR author = 'user') ORDER BY updated_at") else { return out };
        let rows = st.query_map(params![sha], |r| {
            Ok((r.get::<_, i64>(0)? as u64, r.get::<_, String>(1)?))
        });
        if let Ok(rows) = rows {
            for (a, v) in rows.flatten() {
                out.insert(a, v);
            }
        }
        out
    }

    pub fn comments(&self, sha: &str, lo: u64, hi: u64) -> HashMap<u64, String> {
        let mut out = HashMap::new();
        let Ok(db) = self.db.lock() else { return out };
        let Ok(mut st) = db.prepare_cached("SELECT addr, value FROM annotations WHERE sha256 = ?1 AND kind = 'comment' AND addr >= ?2 AND addr < ?3") else { return out };
        if let Ok(rows) = st.query_map(params![sha, lo as i64, hi as i64], |r| {
            Ok((r.get::<_, i64>(0)? as u64, r.get::<_, String>(1)?))
        }) {
            for (a, v) in rows.flatten() {
                out.insert(a, v);
            }
        }
        out
    }
}

pub fn kind_str(k: AnnotationKind) -> &'static str {
    match k {
        AnnotationKind::RenameFunction => "rename_function",
        AnnotationKind::RenameVariable => "rename_variable",
        AnnotationKind::Comment => "comment",
        AnnotationKind::Type => "type",
        AnnotationKind::Bookmark => "bookmark",
        AnnotationKind::Tag => "tag",
    }
}

pub fn open_db(path: &Path) -> rusqlite::Result<Connection> {
    let c = Connection::open(path)?;
    c.execute_batch(
        "PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL; PRAGMA cache_size=-2000;",
    )?;
    c.execute_batch(include_str!("../../../migrations/0001_init.sql"))?;
    Ok(c)
}

/// Bump when triage findings change for the same input.
const FINDINGS_REV: u32 = 1;

/// Build a session (without analysis) from a file on disk. `known_info`
/// (stored at registration) avoids re-hashing the file; findings (which
/// include a full-file crypto-constant scan) are cached under `cache_dir`.
pub fn load_session(
    sha: &str,
    path: &Path,
    file_name: &str,
    known_info: Option<FileInfo>,
    cache_dir: Option<&Path>,
) -> Session {
    let blob = match drishti_loader::open(path) {
        Ok(b) => b,
        Err(e) => {
            let empty = Arc::new(Blob::from_vec(Vec::new()));
            let info = drishti_loader::file_info(&empty, file_name, None);
            return Session {
                sha: sha.into(),
                blob: empty,
                image: None,
                info,
                findings: vec![],
                strings: Arc::new(vec![]),
                analysis: None,
                load_error: Some(e.to_string()),
            };
        }
    };
    let (image, load_error) = match drishti_loader::load_image(blob.clone(), None) {
        Ok(i) => (Some(Arc::new(i)), None),
        Err(drishti_loader::LoadError::Unsupported(_)) => (None, None),
        Err(e) => (None, Some(e.to_string())),
    };
    let mut info = match known_info
        .filter(|i| i.sha256 == sha && i.size == blob.as_ref().as_ref().len() as u64)
    {
        Some(i) => i,
        None => drishti_loader::file_info(&blob, file_name, image.as_deref()),
    };
    info.sha256 = sha.to_string();
    if !file_name.is_empty() {
        info.file_name = file_name.to_string();
    }
    let fcache = cache_dir.map(|d| {
        d.join(format!(
            "{sha}-findings-{}-r{FINDINGS_REV}.json",
            drishti_disasm::ENGINE_VERSION
        ))
    });
    let cached: Option<Vec<Finding>> = fcache
        .as_ref()
        .and_then(|p| std::fs::read(p).ok())
        .and_then(|b| serde_json::from_slice(&b).ok());
    let findings = match cached {
        Some(f) => f,
        None => {
            let mut findings = image
                .as_deref()
                .map(drishti_loader::triage::findings)
                .unwrap_or_default();
            if let Some(img) = image.as_deref() {
                findings.extend(drishti_loader::insights::crypto_constants(img));
            }
            if let (Some(p), Ok(json)) = (&fcache, serde_json::to_vec(&findings)) {
                let tmp = p.with_extension(format!("tmp{}", std::process::id()));
                if p.parent()
                    .is_some_and(|d| std::fs::create_dir_all(d).is_ok())
                    && std::fs::write(&tmp, json).is_ok()
                {
                    let _ = std::fs::rename(&tmp, p);
                }
            }
            findings
        }
    };
    let mut strings = drishti_loader::strings(&blob, image.as_deref(), 4, 300_000);
    strings.sort_by_key(|s| s.addr);
    strings.dedup_by_key(|s| s.addr);
    strings.shrink_to_fit();
    Session {
        sha: sha.into(),
        blob,
        image,
        info,
        findings,
        strings: Arc::new(strings),
        analysis: None,
        load_error,
    }
}

/// Add a user annotation directly in the database (used by the MCP server,
/// which runs without the HTTP API). Replaces an earlier rename/comment.
pub fn annotate_offline(
    data_dir: &Path,
    sha: &str,
    addr: u64,
    kind: &str,
    value: &str,
) -> rusqlite::Result<()> {
    std::fs::create_dir_all(data_dir).ok();
    let db = open_db(&data_dir.join("drishti.db"))?;
    db.execute(
        "DELETE FROM annotations WHERE sha256=?1 AND addr=?2 AND kind=?3 AND author='user'",
        params![sha, addr as i64, kind],
    )?;
    let now = crate::util::now();
    db.execute(
        "INSERT INTO annotations (id, sha256, addr, kind, value, scope, author, ai_status, created_at, updated_at) VALUES (?1,?2,?3,?4,?5,NULL,'user',NULL,?6,?6)",
        params![crate::util::new_id(), sha, addr as i64, kind, value, now],
    )?;
    Ok(())
}

/// Function renames stored for `sha` (offline access).
pub fn renames_offline(data_dir: &Path, sha: &str) -> HashMap<u64, String> {
    let mut out = HashMap::new();
    let Ok(db) = open_db(&data_dir.join("drishti.db")) else {
        return out;
    };
    let Ok(mut st) = db.prepare("SELECT addr, value FROM annotations WHERE sha256 = ?1 AND kind = 'rename_function' ORDER BY updated_at") else { return out };
    if let Ok(rows) = st.query_map(params![sha], |r| {
        Ok((r.get::<_, i64>(0)? as u64, r.get::<_, String>(1)?))
    }) {
        out.extend(rows.flatten());
    }
    out
}
