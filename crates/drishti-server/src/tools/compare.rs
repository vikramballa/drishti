//! Engine comparison (spec §7.8, Day 13): Drishti's functions against
//! Ghidra's and radare2's for the same file, scored by
//! `drishti_disasm::compare`.
//!
//! Each external engine runs once per file, in the sandbox, as a background
//! task (Ghidra through `DrishtiFunctions.java` on the same per-file project
//! the decompiler uses; radare2 with `aaa`, its function list and its call
//! references). Their function lists are cached; the comparison itself is
//! cheap and computed per request, so sorting and paging need no re-run.

use super::decompile::{FULL_ANALYSIS_MAX, GhidraJob, fat_slice, ghidra_script};
use super::{RunSpec, def, load_result, locate, result_path, run, spawn_task, task, version};
use crate::api::{R, bad, valid_sha};
use crate::state::{Session, Shared};
use axum::Json;
use axum::extract::{Path, Query, State};
use drishti_disasm::compare::{self, EngineFn, EngineList};
use drishti_model::Addr;
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::HashMap;
use std::ffi::OsString;
use std::path::Path as FsPath;
use std::sync::Arc;
use std::time::Duration;

/// Bumped when the exported function-list format changes.
const FNLIST_REV: &str = "2";
/// radare2's `aaa` gets slow on big files; Ghidra is limited to files it
/// fully analyses (above that it imports without analysis, so its function
/// list would be nearly empty).
const R2_MAX: u64 = 32 << 20;
const ENGINES: [&str; 2] = ["ghidra", "radare2"];

#[derive(Deserialize)]
pub struct CompareQ {
    /// `score` (default: most disagreement first) or `addr`.
    #[serde(default)]
    sort: Option<String>,
    #[serde(default)]
    offset: Option<usize>,
    #[serde(default)]
    limit: Option<usize>,
    /// Only the functions this engine alone found.
    #[serde(default)]
    only: Option<String>,
    /// Comma-separated subset of `ghidra,radare2`.
    #[serde(default)]
    engines: Option<String>,
}

/// `GET /binaries/{sha}/compare?sort=score|addr&offset=&limit=&only=&engines=`
///
/// Starts any engine that hasn't run on this file yet and returns what is
/// known so far: `status` is `running` until every requested engine has
/// finished (or failed / is missing), then `done`.
pub async fn compare(
    State(st): State<Shared>,
    Path(sha): Path<String>,
    Query(q): Query<CompareQ>,
) -> R<Json<Value>> {
    valid_sha(&sha)?;
    let s = crate::api::analysed(&st, &sha).await?;
    if !s.info.format.is_native() || s.image.is_none() {
        return Err(bad(
            "comparing engines works on programs (machine code) only",
        ));
    }
    let wanted: Vec<&str> = match q.engines.as_deref() {
        None | Some("") => ENGINES.to_vec(),
        Some(list) => {
            let w: Vec<&str> = ENGINES
                .into_iter()
                .filter(|e| list.split(',').any(|x| x.trim() == *e))
                .collect();
            if w.is_empty() {
                return Err(bad("engines must be ghidra and/or radare2"));
            }
            w
        }
    };
    let mut statuses = Vec::new();
    let mut lists = vec![drishti_list(&s)];
    let mut pending = false;
    for engine in wanted {
        let (status, list) = engine_state(&st, &s, engine).await;
        pending |= matches!(status["status"].as_str(), Some("queued" | "running"));
        statuses.push(status);
        if let Some(l) = list {
            lists.push(l);
        }
    }
    statuses.insert(
        0,
        json!({"engine": "drishti", "status": "done", "functions": lists[0].functions.len()}),
    );
    if lists.len() < 2 {
        return Ok(Json(json!({
            "status": if pending { "running" } else { "unavailable" },
            "engines": statuses,
            "message": if pending { "The other engines are still analysing this file." } else { "No other engine could analyse this file (see each engine's status)." },
        })));
    }
    let mut c = compare::compare(&lists);
    if let Some(only) = q.only.as_deref() {
        c.rows
            .retain(|r| r.found_by == 1 && r.engines.get(only).is_some_and(Option::is_some));
    }
    match q.sort.as_deref() {
        Some("addr") => {}
        Some("score") | None => compare::sort_by_disagreement(&mut c.rows),
        Some(_) => return Err(bad("sort must be score or addr")),
    }
    let total = c.rows.len();
    let offset = q.offset.unwrap_or(0).min(total);
    let limit = q.limit.unwrap_or(200).clamp(1, 5000);
    let rows: Vec<Value> = c
        .rows
        .iter()
        .skip(offset)
        .take(limit)
        .map(|r| {
            json!({
                "addr": Addr(r.entry),
                "name": r.name,
                "score": r.score,
                "found_by": r.found_by,
                "boundary_agree": r.boundary_agree,
                "block_diff": r.block_diff,
                "call_jaccard": r.call_jaccard,
                "engines": r.engines,
            })
        })
        .collect();
    Ok(Json(json!({
        "status": if pending { "running" } else { "done" },
        "engines": statuses,
        "compared": c.engines,
        "summary": c.summary,
        "total": total,
        "offset": offset,
        "limit": limit,
        "functions": rows,
    })))
}

/// Drishti's own functions, from the analysis.
fn drishti_list(s: &Session) -> EngineList {
    let functions = s
        .analysis
        .as_ref()
        .map(|a| {
            a.functions
                .iter()
                .map(|f| EngineFn {
                    entry: f.entry,
                    size: f.size,
                    blocks: f.nblocks,
                    calls: f.calls.to_vec(),
                    name: Some(f.name.to_string()),
                })
                .collect()
        })
        .unwrap_or_default();
    EngineList {
        engine: "drishti".into(),
        functions,
    }
}

/// One engine's status for this file, plus its function list once known.
/// Starts the engine's background run when nothing is cached or running.
async fn engine_state(
    st: &Shared,
    s: &Arc<Session>,
    engine: &'static str,
) -> (Value, Option<EngineList>) {
    let Some(t) = def(engine) else {
        return (json!({"engine": engine, "status": "missing"}), None);
    };
    let Some(bin) = locate(t) else {
        return (
            json!({"engine": engine, "status": "missing", "install": t.install,
                   "message": format!("{} is not installed. Install it with: {}", t.name, t.install)}),
            None,
        );
    };
    if engine == "ghidra" && super::java_home().is_none() {
        return (
            json!({"engine": engine, "status": "missing", "install": "brew install openjdk@25",
                   "message": "Ghidra needs Java 25. Install it with: brew install openjdk@25"}),
            None,
        );
    }
    let max = if engine == "ghidra" {
        FULL_ANALYSIS_MAX
    } else {
        R2_MAX
    };
    if s.info.size > max {
        return (
            json!({"engine": engine, "status": "skipped",
                   "message": format!("{} only takes part for files up to {} MB (this one is {} MB).", t.name, max >> 20, s.info.size >> 20)}),
            None,
        );
    }
    let ver = version(t, &bin).await.unwrap_or_default();
    let rf = result_path(
        st,
        &format!("fnlist_{engine}"),
        &s.sha,
        &format!("{ver}|{FNLIST_REV}"),
    );
    if let Some(v) = load_result(&rf)
        && let Ok(l) = serde_json::from_value::<EngineList>(v["list"].clone())
    {
        return (
            json!({"engine": engine, "status": "done", "version": ver, "functions": l.functions.len(),
                   "duration_ms": v["duration_ms"]}),
            Some(l),
        );
    }
    let key = format!("compare-{engine}:{}", s.sha);
    if let Some(tk) = task(&key) {
        match tk.status {
            "queued" | "running" => {
                return (
                    json!({"engine": engine, "status": tk.status, "elapsed_s": tk.started.elapsed().as_secs()}),
                    None,
                );
            }
            "failed" => {
                // Report once, then allow a retry.
                if let Ok(mut m) = super::tasks().lock() {
                    m.remove(&key);
                }
                return (
                    json!({"engine": engine, "status": "failed", "message": tk.error}),
                    None,
                );
            }
            _ => {}
        }
    }
    let (st2, s2) = (st.clone(), s.clone());
    spawn_task(st, key, t.heavy, async move {
        let input = st2.binary_location(&s2.sha).ok_or("file not found")?;
        let t0 = std::time::Instant::now();
        let list = match engine {
            "ghidra" => ghidra_functions(&st2, &bin, &input, &s2).await?,
            _ => radare2_functions(&st2, &bin, &input, &s2).await?,
        };
        let v = json!({"engine": engine, "version": ver, "duration_ms": t0.elapsed().as_millis() as u64, "list": list});
        super::store_result(&rf, &v);
        Ok(())
    });
    (json!({"engine": engine, "status": "queued"}), None)
}

fn hex(v: &Value) -> Option<u64> {
    u64::from_str_radix(v.as_str()?.trim_start_matches("0x"), 16).ok()
}

/// Parse `DrishtiFunctions.java` output.
fn parse_ghidra(v: &Value) -> EngineList {
    let functions = v["functions"]
        .as_array()
        .map(|fs| {
            fs.iter()
                .filter_map(|f| {
                    Some(EngineFn {
                        entry: hex(&f["entry"])?,
                        size: f["size"].as_u64().unwrap_or(0),
                        blocks: f["blocks"].as_u64().unwrap_or(0).min(u64::from(u32::MAX)) as u32,
                        calls: f["calls"]
                            .as_array()
                            .map(|c| c.iter().filter_map(hex).collect())
                            .unwrap_or_default(),
                        name: f["name"].as_str().map(str::to_string),
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    EngineList {
        engine: "ghidra".into(),
        functions,
    }
}

async fn ghidra_functions(
    st: &Shared,
    bin: &FsPath,
    input: &FsPath,
    s: &Arc<Session>,
) -> Result<EngineList, String> {
    let job = GhidraJob {
        script: "DrishtiFunctions.java",
        out_name: "functions.json".into(),
        args: Vec::new(),
        timeout: Duration::from_secs(600),
    };
    let (v, _) = ghidra_script(st, bin, input, s, job).await?;
    Ok(parse_ghidra(&v))
}

/// Section markers between the commands' outputs.
const M_IE: &str = "DRISHTI_ENTRY";
const M_AFL: &str = "DRISHTI_FUNCTIONS";
const M_AX: &str = "DRISHTI_XREFS";

async fn radare2_functions(
    st: &Shared,
    bin: &FsPath,
    input: &FsPath,
    s: &Arc<Session>,
) -> Result<EngineList, String> {
    let t = def("radare2").ok_or("radare2 unknown")?;
    let work = super::tools_dir(st)
        .join("tmp")
        .join(format!("r2c-{}", crate::util::new_id()));
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
    args.push(format!("aaa; ?e {M_IE}; iej; ?e {M_AFL}; aflj; ?e {M_AX}; axl~CALL,CODE").into());
    // A universal binary's analysed slice as its own file (see `fat_slice`).
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
            env: vec![("R2_NOPLUGINS".into(), "1".into())],
            timeout: Duration::from_secs(600),
            stdout_cap: 128 << 20,
        },
    )
    .await;
    let _ = std::fs::remove_dir_all(&work);
    let o = o?;
    if o.timed_out {
        return Err("radare2 took too long to analyse this file".into());
    }
    let out = String::from_utf8_lossy(&o.stdout);
    let drishti_entry = s.image.as_deref().and_then(|i| i.entry);
    parse_r2(&out, drishti_entry).ok_or_else(|| {
        format!(
            "radare2 produced no function list{}",
            if o.stderr.is_empty() {
                String::new()
            } else {
                format!(": {}", o.stderr.chars().take(200).collect::<String>())
            }
        )
    })
}

/// Parse radare2's output: `iej` (to line up addresses with Drishti's via
/// the entry point), `aflj` (functions) and `axl~CALL,CODE` lines
/// (`name from > CALL:--x > to target`). Calls are direct CALL references
/// plus CODE jumps that land on another function's entry (tail calls),
/// attributed to the function whose range holds the call site.
fn parse_r2(out: &str, drishti_entry: Option<u64>) -> Option<EngineList> {
    let mut section = "";
    let (mut ie, mut afl) = (None::<Value>, None::<Value>);
    let mut refs: Vec<(u64, u64, bool)> = Vec::new();
    for line in out.lines() {
        let l = line.trim();
        if l == M_IE || l == M_AFL || l == M_AX {
            section = if l == M_IE {
                "ie"
            } else if l == M_AFL {
                "afl"
            } else {
                "ax"
            };
            continue;
        }
        match section {
            "ie" if ie.is_none() && l.starts_with('[') => ie = serde_json::from_str(l).ok(),
            "afl" if afl.is_none() && l.starts_with('[') => afl = serde_json::from_str(l).ok(),
            "ax" => {
                let tok: Vec<&str> = l.split_whitespace().collect();
                let Some(i) = tok
                    .iter()
                    .position(|t| t.starts_with("CALL") || t.starts_with("CODE"))
                else {
                    continue;
                };
                let p = |t: Option<&&str>| {
                    t.and_then(|t| u64::from_str_radix(t.trim_start_matches("0x"), 16).ok())
                };
                if let (Some(from), Some(to)) = (
                    p(i.checked_sub(2).and_then(|j| tok.get(j))),
                    p(tok.get(i + 2)),
                ) {
                    refs.push((from, to, tok[i].starts_with("CALL")));
                }
            }
            _ => {}
        }
    }
    let afl = afl?;
    let fns = afl.as_array()?;
    // radare2 and Drishti may map position-independent files differently;
    // shift by the entry-point difference when both know it.
    let r2_entry = ie
        .as_ref()
        .and_then(|v| v.as_array())
        .and_then(|a| a.iter().find(|e| e["type"] == "program").or(a.first()))
        .and_then(|e| e["vaddr"].as_u64());
    let delta = match (r2_entry, drishti_entry) {
        (Some(r), Some(d)) => r.wrapping_sub(d),
        _ => 0,
    };
    let fix = |a: u64| a.wrapping_sub(delta);
    let mut functions: Vec<EngineFn> = fns
        .iter()
        .filter_map(|f| {
            let entry = f["addr"].as_u64().or_else(|| f["offset"].as_u64())?;
            // Extent like Drishti's: last byte + 1 − entry (`size` is the same
            // for contiguous functions; `maxaddr` is exclusive).
            let size = f["maxaddr"]
                .as_u64()
                .map(|m| m.saturating_sub(entry))
                .or_else(|| f["size"].as_u64())
                .unwrap_or(0);
            Some(EngineFn {
                entry: fix(entry),
                size,
                blocks: f["nbbs"].as_u64().unwrap_or(0).min(u64::from(u32::MAX)) as u32,
                calls: Vec::new(),
                name: f["name"].as_str().map(str::to_string),
            })
        })
        .collect();
    functions.sort_by_key(|f| f.entry);
    let entries: HashMap<u64, usize> = functions
        .iter()
        .enumerate()
        .map(|(i, f)| (f.entry, i))
        .collect();
    for (from, to, call) in refs {
        let (from, to) = (fix(from), fix(to));
        // Caller: the function with the greatest entry ≤ from whose extent holds it.
        let idx = functions.partition_point(|f| f.entry <= from);
        let Some(ci) = idx.checked_sub(1) else {
            continue;
        };
        let caller = &functions[ci];
        if from >= caller.entry.saturating_add(caller.size.max(1)) {
            continue;
        }
        if !call && (!entries.contains_key(&to) || to == caller.entry) {
            continue;
        }
        functions[ci].calls.push(to);
    }
    Some(EngineList {
        engine: "radare2".into(),
        functions,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn radare2_output_is_parsed() {
        let out = format!(
            "{M_IE}\n[{{\"vaddr\":4096,\"type\":\"program\"}}]\n{M_AFL}\n\
             [{{\"addr\":4096,\"name\":\"main\",\"size\":32,\"maxaddr\":4128,\"nbbs\":3}},\
              {{\"addr\":4200,\"name\":\"sym.func.1068\",\"size\":8,\"maxaddr\":4208,\"nbbs\":1}},\
              {{\"addr\":4300,\"name\":\"sym.imp.puts\",\"size\":12,\"maxaddr\":4312,\"nbbs\":1}}]\n\
             {M_AX}\n\
             \u{20}  main+8 0x1008 > CALL:--x > 0x10cc sym.imp.puts\n\
             \u{20}  main+12 0x100c > CALL:--x > 0x10cc sym.imp.puts\n\
             \u{20}  main+20 0x1014 > CODE:--x > 0x1004 main+4\n\
             \u{20}  sym.func.1068+4 0x106c > CODE:--x > 0x1000 main\n"
        );
        // Drishti saw the entry at 0x100 lower (e.g. a different PIE base).
        let l = parse_r2(&out, Some(0x1000 - 0x100)).expect("parsed");
        assert_eq!(l.functions.len(), 3);
        let main = &l.functions[0];
        assert_eq!((main.entry, main.size, main.blocks), (0xf00, 32, 3));
        // Two calls to puts; the jump inside main is not a tail call.
        assert_eq!(main.calls, vec![0xfcc, 0xfcc]);
        // A jump to another function's entry is a tail call.
        assert_eq!(l.functions[1].calls, vec![0xf00]);
        assert_eq!(l.functions[2].name.as_deref(), Some("sym.imp.puts"));
        assert!(parse_r2("garbage", None).is_none());
    }

    #[test]
    fn ghidra_output_is_parsed() {
        let v: Value = serde_json::from_str(
            r#"{"image_base":"100000000","functions":[
              {"entry":"1000004b0","size":312,"blocks":10,"thunk":false,"name":"entry","calls":["1000005e8","100000950"]},
              {"entry":"not-hex","size":1,"blocks":1,"calls":[]}]}"#,
        )
        .expect("json");
        let l = parse_ghidra(&v);
        assert_eq!(l.functions.len(), 1);
        assert_eq!(l.functions[0].entry, 0x1_0000_04b0);
        assert_eq!(l.functions[0].calls, vec![0x1_0000_05e8, 0x1_0000_0950]);
    }
}
