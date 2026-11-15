//! Readable C-like code for one function, from Ghidra (headless) or
//! radare2, on demand. Results are cached per (file, engine, version,
//! address). Ghidra keeps one project per file, so only the first request
//! pays for the import (a few seconds for small programs, a few minutes
//! for very large apps); later functions take a few seconds each.

use super::{
    RunSpec, def, input_link, locate, result_path, run, spawn_task, task, tools_dir, version,
    work_dir,
};
use crate::api::{R, bad, not_found, valid_sha};
use crate::state::{Session, Shared};
use axum::Json;
use axum::extract::{Query, State};
use drishti_model::{Addr, Format};
use serde::Deserialize;
use serde_json::{Value, json};
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

const SCRIPTS: [(&str, &str); 2] = [
    (
        "DrishtiDecompile.java",
        include_str!("../../scripts/DrishtiDecompile.java"),
    ),
    (
        "DrishtiFunctions.java",
        include_str!("../../scripts/DrishtiFunctions.java"),
    ),
];
/// Above this size Ghidra imports without auto-analysis (which would take
/// a very long time and several GB on large apps) and builds only the
/// requested functions.
pub(super) const FULL_ANALYSIS_MAX: u64 = 12 << 20;

#[derive(Deserialize)]
pub struct DecompQ {
    addr: String,
    #[serde(default)]
    engine: Option<String>,
}

fn script_dir(st: &Shared) -> Result<PathBuf, String> {
    let d = tools_dir(st).join("scripts");
    std::fs::create_dir_all(&d).map_err(|e| e.to_string())?;
    for (name, src) in SCRIPTS {
        let p = d.join(name);
        if std::fs::read_to_string(&p).ok().as_deref() != Some(src) {
            std::fs::write(&p, src).map_err(|e| e.to_string())?;
        }
    }
    Ok(d)
}

fn result_file(st: &Shared, engine: &str, sha: &str, ver: &str, addr: u64) -> PathBuf {
    let base = result_path(st, &format!("decomp-{engine}"), sha, ver);
    base.with_file_name(format!(
        "{}-{addr:x}.json",
        base.file_stem()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_default()
    ))
}

/// `GET /binaries/{sha}/decompile?addr=&engine=ghidra|radare2`
/// Returns the cached result, or starts the work and reports progress.
pub async fn decompile(
    State(st): State<Shared>,
    axum::extract::Path(sha): axum::extract::Path<String>,
    Query(q): Query<DecompQ>,
) -> R<Json<Value>> {
    valid_sha(&sha)?;
    let addr = Addr::parse(&q.addr)
        .map(|a| a.0)
        .ok_or_else(|| bad("invalid address"))?;
    let s = crate::api::session(&st, &sha).await?;
    if !s.info.format.is_native() || s.image.is_none() {
        return Err(bad("decompiling works on programs (machine code) only"));
    }
    // Default: Ghidra when installed, else radare2.
    let engine: &'static str = match q.engine.as_deref() {
        Some("ghidra") => "ghidra",
        Some("radare2") => "radare2",
        Some(_) => return Err(bad("engine must be ghidra or radare2")),
        None if def("ghidra").and_then(locate).is_some() => "ghidra",
        None => "radare2",
    };
    let t = def(engine).ok_or_else(|| not_found("unknown engine"))?;
    let Some(bin) = locate(t) else {
        return Ok(Json(
            json!({"status": "missing", "engine": engine, "install": t.install,
                               "message": format!("{} is not installed. Install it with: {}", t.name, t.install)}),
        ));
    };
    if engine == "ghidra" && super::java_home().is_none() {
        return Ok(Json(
            json!({"status": "missing", "engine": engine, "install": "brew install openjdk@25",
                               "message": "Ghidra needs Java 25. Install it with: brew install openjdk@25"}),
        ));
    }
    let ver = version(t, &bin).await.unwrap_or_default();
    let rf = result_file(&st, engine, &sha, &ver, addr);
    if let Some(v) = super::load_result(&rf) {
        return Ok(Json(v));
    }
    let key = format!("decomp-{engine}:{sha}:{addr:x}");
    if let Some(tk) = task(&key) {
        match tk.status {
            "queued" | "running" => {
                return Ok(Json(
                    json!({"status": tk.status, "engine": engine, "elapsed_s": tk.started.elapsed().as_secs(),
                                       "first_time": engine == "ghidra" && !ghidra_imported(&st, &sha)}),
                ));
            }
            "failed" => {
                // Report once, then allow a retry.
                if let Ok(mut m) = super::tasks().lock() {
                    m.remove(&key);
                }
                return Ok(Json(
                    json!({"status": "failed", "engine": engine, "message": tk.error}),
                ));
            }
            _ => {}
        }
    }
    let (st2, sha2) = (st.clone(), sha.clone());
    let first = engine == "ghidra" && !ghidra_imported(&st, &sha);
    spawn_task(&st, key, t.heavy, async move {
        let input = st2.binary_location(&sha2).ok_or("file not found")?;
        let v = match engine {
            "ghidra" => ghidra(&st2, &bin, &input, &s, addr).await?,
            _ => radare2(&st2, &bin, &input, &s, addr).await?,
        };
        let mut v = v;
        v["status"] = json!("done");
        v["engine"] = json!(engine);
        v["version"] = json!(ver);
        v["addr"] = json!(Addr(addr));
        super::store_result(&rf, &v);
        Ok(())
    });
    Ok(Json(
        json!({"status": "queued", "engine": engine, "first_time": first}),
    ))
}

fn ghidra_imported(st: &Shared, sha: &str) -> bool {
    work_dir(st, "ghidra", sha).join("imported").is_file()
}

/// The analysed slice of a universal binary, written once to
/// `work/slice.bin`; `None` for other files. External tools get this file
/// instead of the universal one: Ghidra would import the first slice, and
/// radare2's `-a/-b` can't tell two slices of the same architecture apart
/// (`/bin/ls` has both `arm64e` and `arm64e.x1`).
pub(super) fn fat_slice(work: &Path, s: &Session) -> Result<Option<PathBuf>, String> {
    if s.info.format != Format::MachoFat {
        return Ok(None);
    }
    let img = s.image.as_deref().ok_or("no image")?;
    let out = work.join("slice.bin");
    if !out.is_file() {
        let bytes = img.blob.as_ref().as_ref();
        let end = img
            .slice_offset
            .checked_add(img.slice_len)
            .ok_or("bad slice")?;
        let slice = bytes.get(img.slice_offset..end).ok_or("bad slice")?;
        std::fs::create_dir_all(work).map_err(|e| e.to_string())?;
        std::fs::write(&out, slice).map_err(|e| e.to_string())?;
    }
    Ok(Some(out))
}

/// Ghidra input: the analysed slice of a universal binary, else the file.
fn ghidra_input(work: &Path, input: &Path, s: &Session) -> Result<PathBuf, String> {
    Ok(match fat_slice(work, s)? {
        Some(p) => p,
        None => input_link(work, input, s.info.format),
    })
}

/// A Drishti Ghidra script run: script file, its output file name (in the
/// work folder), arguments after `<out.json> <image-base>`, and the time
/// limit once the file is imported.
pub(super) struct GhidraJob {
    pub script: &'static str,
    pub out_name: String,
    pub args: Vec<OsString>,
    pub timeout: Duration,
}

/// Run one of the Drishti Ghidra scripts against the file's Ghidra project,
/// importing it first if needed (full auto-analysis for files up to
/// [`FULL_ANALYSIS_MAX`]). The script writes JSON to `out`, which is
/// returned parsed. `timeout` applies once the file is imported.
pub(super) async fn ghidra_script(
    st: &Shared,
    bin: &Path,
    input: &Path,
    s: &Arc<Session>,
    job: GhidraJob,
) -> Result<(Value, u64), String> {
    let GhidraJob {
        script,
        out_name,
        args: script_args,
        timeout,
    } = job;
    let t = def("ghidra").ok_or("ghidra unknown")?;
    let work = work_dir(st, "ghidra", &s.sha);
    std::fs::create_dir_all(work.join("proj")).map_err(|e| e.to_string())?;
    let scripts = script_dir(st)?;
    let img = s.image.as_deref().ok_or("no image")?;
    let out = work.join(&out_name);
    let _ = std::fs::remove_file(&out);
    let marker = work.join("imported");
    let mut args: Vec<OsString> = vec![work.join("proj").into(), "drishti".into()];
    let first = !marker.is_file();
    let prog_name;
    if first {
        let inp = ghidra_input(&work, input, s)?;
        prog_name = inp
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        args.push("-import".into());
        args.push(inp.into());
        if s.info.size > FULL_ANALYSIS_MAX {
            args.push("-noanalysis".into());
        }
    } else {
        prog_name = std::fs::read_to_string(&marker)
            .map_err(|e| e.to_string())?
            .trim()
            .to_string();
        args.extend([
            "-process".into(),
            prog_name.clone().into(),
            "-noanalysis".into(),
            "-readOnly".into(),
        ]);
    }
    args.extend([
        "-scriptPath".into(),
        scripts.into_os_string(),
        "-postScript".into(),
        script.into(),
        out.clone().into_os_string(),
        format!("{:x}", img.image_base).into(),
    ]);
    args.extend(script_args);
    args.extend(["-max-cpu".into(), "2".into()]);
    let o = run(
        st,
        RunSpec {
            tool: t,
            bin: bin.to_path_buf(),
            args,
            work: work.clone(),
            extra_writable: Vec::new(),
            env: vec![("GHIDRA_MAXMEM".into(), "2G".into())],
            timeout: if first {
                Duration::from_secs(t.timeout_s)
            } else {
                timeout
            },
            stdout_cap: 256 << 10,
        },
    )
    .await?;
    if o.timed_out {
        return Err(if first {
            "Ghidra took too long to load this file. Very large apps can take longer than 15 minutes; try radare2 instead.".into()
        } else {
            "Ghidra took too long on this request.".into()
        });
    }
    let v: Value = match std::fs::read(&out)
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
    {
        Some(v) => v,
        None => {
            let log = String::from_utf8_lossy(&o.stdout);
            let why = log
                .lines()
                .rev()
                .find(|l| l.contains("ERROR") || l.contains("Exception"))
                .unwrap_or("no output");
            return Err(format!(
                "Ghidra failed: {}",
                why.chars().take(300).collect::<String>()
            ));
        }
    };
    let _ = std::fs::remove_file(&out);
    if first {
        std::fs::write(&marker, &prog_name).map_err(|e| e.to_string())?;
    }
    Ok((v, o.duration_ms))
}

async fn ghidra(
    st: &Shared,
    bin: &Path,
    input: &Path,
    s: &Arc<Session>,
    addr: u64,
) -> Result<Value, String> {
    let job = GhidraJob {
        script: "DrishtiDecompile.java",
        out_name: format!("out-{addr:x}.json"),
        args: vec![format!("{addr:x}").into()],
        timeout: Duration::from_secs(240),
    };
    let (v, ms) = ghidra_script(st, bin, input, s, job).await?;
    let f = v["functions"].get(0).cloned().unwrap_or(Value::Null);
    if let Some(e) = f["error"].as_str() {
        return Err(format!("Ghidra: {e}"));
    }
    Ok(
        json!({"name": f["name"], "signature": f["signature"], "code": tidy(f["code"].as_str().unwrap_or("")),
              "duration_ms": ms, "full_analysis": s.info.size <= FULL_ANALYSIS_MAX}),
    )
}

async fn radare2(
    st: &Shared,
    bin: &Path,
    input: &Path,
    s: &Arc<Session>,
    addr: u64,
) -> Result<Value, String> {
    let t = def("radare2").ok_or("radare2 unknown")?;
    let work = super::tools_dir(st)
        .join("tmp")
        .join(format!("r2-{}", crate::util::new_id()));
    let pdg = super::runners::r2ghidra_available().await;
    let mut args: Vec<OsString> = vec![
        "-q".into(),
        "-2".into(),
        "-e".into(),
        "scr.color=0".into(),
        "-e".into(),
        "bin.relocs.apply=true".into(),
        "-e".into(),
        "scr.interactive=false".into(),
    ];
    args.push("-c".into());
    args.push(format!("s {addr:#x}; af; {}", if pdg { "pdg" } else { "pdc" }).into());
    let slice = fat_slice(&work, s)?;
    args.push(slice.as_deref().unwrap_or(input).as_os_str().to_owned());
    let o = run(
        st,
        RunSpec {
            tool: t,
            bin: bin.to_path_buf(),
            args,
            work: work.clone(),
            extra_writable: Vec::new(),
            env: vec![("R2_NOPLUGINS".into(), if pdg { "0" } else { "1" }.into())],
            timeout: Duration::from_secs(t.timeout_s),
            stdout_cap: 2 << 20,
        },
    )
    .await;
    let _ = std::fs::remove_dir_all(&work);
    let o = o?;
    if o.timed_out {
        return Err("radare2 took too long on this function".into());
    }
    let code = String::from_utf8_lossy(&o.stdout).into_owned();
    if code.trim().is_empty() {
        return Err(format!(
            "radare2 produced no output{}",
            if o.stderr.is_empty() {
                String::new()
            } else {
                format!(": {}", o.stderr.chars().take(200).collect::<String>())
            }
        ));
    }
    Ok(
        json!({"code": tidy(&code), "duration_ms": o.duration_ms, "quality": if pdg { "r2ghidra" } else { "basic" }}),
    )
}

/// Trim blank lines Ghidra puts around the function.
fn tidy(c: &str) -> String {
    c.trim_matches('\n').replace("\n\n\n", "\n\n")
}

/// Decompiled code already cached for a function (any engine/version):
/// (engine name, code). Used to give the AI better context.
pub async fn cached_code(st: &Shared, sha: &str, addr: u64) -> Option<(String, String)> {
    let dir = tools_dir(st).join("results");
    let suffix = format!("-{addr:x}.json");
    let rd = std::fs::read_dir(&dir).ok()?;
    let mut hits: Vec<(String, PathBuf)> = rd
        .flatten()
        .filter_map(|e| {
            let n = e.file_name().to_string_lossy().into_owned();
            let eng = if n.starts_with(&format!("decomp-ghidra-{sha}-")) {
                "Ghidra"
            } else if n.starts_with(&format!("decomp-radare2-{sha}-")) {
                "radare2"
            } else {
                return None;
            };
            n.ends_with(&suffix).then(|| (eng.to_string(), e.path()))
        })
        .collect();
    hits.sort_by_key(|h| h.0 != "Ghidra");
    let (eng, p) = hits.into_iter().next()?;
    let v = super::load_result(&p)?;
    Some((eng, v["code"].as_str()?.to_string()))
}
