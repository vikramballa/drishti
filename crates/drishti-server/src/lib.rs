//! Drishti API server: REST + WebSocket, job scheduler, storage, and the
//! embedded web UI — all in one small process (spec §7.12, §7.13).
#![forbid(unsafe_code)]

pub mod ai;
pub mod api;
pub mod bundle;
pub mod engines;
pub mod extra;
pub mod lookup;
pub mod mac;
pub mod net;
pub mod origin;
pub mod plain;
pub mod search;
pub mod secrets;
pub mod state;
pub mod tools;
pub mod util;

use axum::Router;
use axum::extract::{DefaultBodyLimit, Request, State};
use axum::http::{StatusCode, Uri, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, patch, post};
use state::{AppState, Shared};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub struct Config {
    pub host: String,
    pub port: u16,
    pub data_dir: PathBuf,
}

/// `~/.drishti` (or `$DRISHTI_DATA`).
pub fn default_data_dir() -> PathBuf {
    if let Some(d) = std::env::var_os("DRISHTI_DATA") {
        return PathBuf::from(d);
    }
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".drishti")
}

#[derive(rust_embed::RustEmbed)]
#[folder = "../../web/dist"]
struct Assets;

async fn static_files(uri: Uri) -> Response {
    let path = uri.path().trim_start_matches('/');
    let path = if path.is_empty() { "index.html" } else { path };
    let (file, name) = match Assets::get(path) {
        Some(f) => (f, path),
        // SPA fallback
        None => match Assets::get("index.html") {
            Some(f) => (f, "index.html"),
            None => return (StatusCode::NOT_FOUND, "UI not built").into_response(),
        },
    };
    let mime = mime_guess::from_path(name).first_or_octet_stream();
    let cache = if name.starts_with("assets/") {
        "public, max-age=31536000, immutable"
    } else {
        "no-cache"
    };
    (
        [
            (header::CONTENT_TYPE, mime.as_ref().to_string()),
            (header::CACHE_CONTROL, cache.to_string()),
        ],
        file.data.into_owned(),
    )
        .into_response()
}

/// Server mode (non-loopback bind) requires `DRISHTI_TOKEN`; requests must
/// send `Authorization: Bearer <token>` (or `?token=` for WebSockets).
async fn auth(State(st): State<Shared>, req: Request, next: Next) -> Response {
    if let Some(tok) = &st.token {
        let hdr = req
            .headers()
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "));
        let qtok = req
            .uri()
            .query()
            .and_then(|q| q.split('&').find_map(|kv| kv.strip_prefix("token=")));
        if hdr != Some(tok.as_str()) && qtok != Some(tok.as_str()) {
            return (StatusCode::UNAUTHORIZED, "missing or invalid token").into_response();
        }
    }
    next.run(req).await
}

pub fn router(st: Shared) -> Router {
    use api::*;
    let v1 = Router::new()
        .route("/health", get(health))
        .route("/engines", get(engines))
        .route("/openapi.json", get(openapi))
        .route(
            "/binaries",
            get(list_binaries)
                .post(upload)
                .layer(DefaultBodyLimit::disable()),
        )
        .route("/binaries/open", post(open_path))
        .route("/binaries/{sha}", get(get_binary))
        .route("/binaries/{sha}/bytes", get(bytes))
        .route("/binaries/{sha}/strings", get(strings))
        .route("/binaries/{sha}/functions", get(functions))
        .route("/binaries/{sha}/functions/{addr}", get(function_detail))
        .route("/binaries/{sha}/disasm", get(disasm))
        .route("/binaries/{sha}/xrefs", get(xrefs))
        .route("/binaries/{sha}/callgraph", get(callgraph))
        .route("/binaries/{sha}/resolve", get(resolve))
        .route(
            "/binaries/{sha}/annotations",
            get(list_annotations).post(add_annotation),
        )
        .route(
            "/binaries/{sha}/annotations/{id}",
            patch(patch_annotation).delete(delete_annotation),
        )
        .route("/binaries/{sha}/symbols", get(t_symbols))
        .route("/binaries/{sha}/imports", get(t_imports))
        .route("/binaries/{sha}/exports", get(t_exports))
        .route("/jobs", post(create_job))
        .route("/jobs/{id}", get(get_job).delete(cancel_job))
        .route("/jobs/{id}/events", get(ws_job))
        .route("/events", get(ws_all))
        .route("/settings", get(get_settings).put(put_settings))
        .route("/binaries/{sha}/insights", get(extra::insights))
        .route("/binaries/{sha}/search", get(search::search))
        .route("/search", get(search::search_all))
        .route("/binaries/{sha}/diff", get(extra::diff))
        .route("/binaries/{sha}/report.md", get(extra::report))
        .route("/local/apps", get(extra::local_apps))
        .route("/ai/status", get(ai::status))
        .route("/binaries/{sha}/ai/ask", post(ai::ask))
        .route("/binaries/{sha}/ai/facts", get(ai::facts))
        .route("/ai/cloud/{id}/models", get(ai::cloud_models_ep))
        .route("/secrets", get(secrets_get))
        .route(
            "/secrets/{id}",
            axum::routing::put(secrets_put).delete(secrets_delete),
        )
        .route("/tools", get(tools::list))
        .route("/tools/{id}/setup", post(tools::setup))
        .route("/binaries/{sha}/tools", get(tools::for_binary))
        .route("/binaries/{sha}/tools/{id}", post(tools::run_on))
        .route(
            "/binaries/{sha}/decompile",
            get(tools::decompile::decompile),
        )
        .route("/binaries/{sha}/source", get(tools::source::browse))
        .route("/binaries/{sha}/lookups", get(lookup::list))
        .route("/binaries/{sha}/lookups/{id}", post(lookup::run))
        .route("/binaries/{sha}/trust", get(extra::trust))
        .route("/binaries/{sha}/vulns", get(extra::vulns))
        .route("/binaries/{sha}/nl-query", post(extra::nl_query))
        .route("/local/startup", get(mac::startup))
        .route("/local/scan-apps", get(mac::scan_apps))
        .route_layer(middleware::from_fn_with_state(st.clone(), auth));
    Router::new()
        .nest("/api/v1", v1)
        .fallback(static_files)
        .with_state(st)
}

async fn secrets_get(State(st): State<Shared>) -> axum::Json<serde_json::Value> {
    axum::Json(secrets::status(&st))
}

#[derive(serde::Deserialize)]
struct SecretBody {
    value: String,
}

async fn secrets_put(
    State(st): State<Shared>,
    axum::extract::Path(id): axum::extract::Path<String>,
    axum::Json(b): axum::Json<SecretBody>,
) -> Response {
    match secrets::set(&st, &id, Some(&b.value)) {
        Ok(()) => axum::Json(secrets::status(&st)).into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            axum::Json(serde_json::json!({"error": e})),
        )
            .into_response(),
    }
}

async fn secrets_delete(
    State(st): State<Shared>,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Response {
    match secrets::set(&st, &id, None) {
        Ok(()) => axum::Json(secrets::status(&st)).into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            axum::Json(serde_json::json!({"error": e})),
        )
            .into_response(),
    }
}

/// Poll in-place files (local mode) and re-analyse when they change — so
/// rebuilding a binary updates the UI live.
async fn watch_files(st: Shared) {
    let mut tick = tokio::time::interval(Duration::from_secs(2));
    loop {
        tick.tick().await;
        let items: Vec<(String, PathBuf, i64)> = st
            .watched
            .lock()
            .map(|w| {
                w.iter()
                    .map(|(k, (p, m))| (k.clone(), p.clone(), *m))
                    .collect()
            })
            .unwrap_or_default();
        for (sha, path, mtime) in items {
            let Ok(meta) = tokio::fs::metadata(&path).await else {
                continue;
            };
            let m = meta
                .modified()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_millis() as i64)
                .unwrap_or(0);
            if m == mtime {
                continue;
            }
            // Wait for writers (linkers) to finish.
            tokio::time::sleep(Duration::from_millis(500)).await;
            if let Ok(mut w) = st.watched.lock() {
                w.remove(&sha);
            }
            match api::open_local(&st, path.clone(), true).await {
                Ok(v) => {
                    let new_sha = v
                        .get("binary_id")
                        .and_then(|s| s.as_str())
                        .unwrap_or("")
                        .to_string();
                    st.emit(state::Event {
                        kind: "binary_changed",
                        job_id: v.get("job_id").and_then(|s| s.as_str()).map(str::to_string),
                        sha256: Some(new_sha),
                        status: None,
                        phase: None,
                        functions: None,
                        instructions: None,
                        message: Some(format!("{}|{}", sha, path.display())),
                    });
                }
                Err(_) => tracing::warn!("re-analysis of {} failed", path.display()),
            }
        }
    }
}

pub fn run(cfg: Config) -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into()))
        .with_target(false)
        .init();
    // Small runtime: 2 async workers; analysis runs on a bounded blocking pool.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .max_blocking_threads(4)
        .enable_all()
        .build()?;
    rt.block_on(serve(cfg))
}

pub async fn serve(cfg: Config) -> anyhow::Result<()> {
    std::fs::create_dir_all(cfg.data_dir.join("blobs"))?;
    let ip: IpAddr = cfg.host.parse().unwrap_or(IpAddr::from([127, 0, 0, 1]));
    let local_mode = ip.is_loopback();
    let token = std::env::var("DRISHTI_TOKEN")
        .ok()
        .filter(|t| !t.is_empty());
    if !local_mode && token.is_none() {
        anyhow::bail!("server mode (binding {ip}) requires DRISHTI_TOKEN to be set");
    }
    let db = state::open_db(&cfg.data_dir.join("drishti.db"))?;
    let (tx, _) = tokio::sync::broadcast::channel(512);
    let slots = std::thread::available_parallelism()
        .map(|n| n.get().clamp(1, 4) / 2)
        .unwrap_or(1)
        .max(1);
    let st: Shared = Arc::new(AppState {
        data_dir: cfg.data_dir.clone(),
        local_mode,
        token,
        upload_limit: std::env::var("DRISHTI_UPLOAD_LIMIT")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(512 * 1024 * 1024),
        db: Mutex::new(db),
        sessions: Mutex::new(Vec::new()),
        session_loads: Mutex::new(HashMap::new()),
        jobs: Mutex::new(HashMap::new()),
        events: tx,
        analysis_slots: tokio::sync::Semaphore::new(slots),
        watched: Mutex::new(HashMap::new()),
    });
    // Mark jobs interrupted by a previous shutdown.
    if let Ok(db) = st.db.lock() {
        let _ = db.execute(
            "UPDATE jobs SET status='interrupted' WHERE status IN ('queued','running')",
            [],
        );
    }
    if local_mode {
        tokio::spawn(watch_files(st.clone()));
    }
    let app = router(st);
    let addr = SocketAddr::new(ip, cfg.port);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    println!(
        "Drishti listening on http://{addr}  (data: {})",
        cfg.data_dir.display()
    );
    axum::serve(listener, app)
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;
    Ok(())
}
