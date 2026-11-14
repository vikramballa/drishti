//! Insight endpoints: security summary, search, diff, report, app picker.

use crate::api::{ApiError, R, analysed, bad, not_found, session, valid_sha};
use crate::state::{Session, Shared};
use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use serde_json::{Value, json};
use std::sync::Arc;

/// Download origin of an in-place file (local mode only; uploads have none).
pub(crate) fn origin_of(st: &Shared, sha: &str) -> Option<drishti_model::FileOrigin> {
    if !st.local_mode {
        return None;
    }
    let p = st
        .binary_location(sha)
        .filter(|p| *p != st.blob_path(sha))?;
    crate::origin::file_origin(&p)
}

/// Document provenance + safety report for formats that have one (PDF).
pub(crate) fn document_of(s: &Session) -> Option<drishti_model::DocumentReport> {
    (s.info.format == drishti_model::Format::Pdf)
        .then(|| drishti_loader::pdf::analyze(s.blob.as_ref().as_ref()))
}

pub(crate) fn build_insights(s: &Session, origin: Option<drishti_model::FileOrigin>) -> Value {
    let img = s.image.as_deref();
    let (hardening, signing) = img
        .map(drishti_loader::insights::hardening)
        .unwrap_or_default();
    let behaviors = img
        .map(|i| drishti_disasm::insights::behaviors(i, s.analysis.as_ref()))
        .unwrap_or_default();
    let iocs = drishti_loader::insights::iocs(&s.strings);
    let document = document_of(s);
    let summary = match &document {
        Some(d) => document_summary(&s.info.file_name, d),
        None => drishti_disasm::insights::summary(
            &s.info,
            img,
            signing.as_ref(),
            &behaviors,
            s.analysis.as_ref().map(|a| a.functions.len()),
        ),
    };
    json!({ "summary": summary, "hardening": hardening, "signing": signing, "behaviors": behaviors, "iocs": iocs,
            "document": document, "origin": origin })
}

/// One-paragraph plain-language summary of a document.
fn document_summary(name: &str, d: &drishti_model::DocumentReport) -> String {
    let pages = match d.pages {
        Some(1) => " with 1 page".to_string(),
        Some(n) => format!(" with {n} pages"),
        None => String::new(),
    };
    let made = d
        .clues
        .iter()
        .find(|c| c.topic == "made_with")
        .map(|c| {
            let t = c.text.split(" (\u{201c}").next().unwrap_or(&c.text);
            format!(" {}.", t.trim_end_matches('.'))
        })
        .unwrap_or_default();
    format!("{name} is a PDF document{pages}.{made} {}", d.verdict)
}

pub async fn insights(State(st): State<Shared>, Path(sha): Path<String>) -> R<Json<Value>> {
    let s = session(&st, &sha).await?;
    let st2 = st.clone();
    Ok(Json(
        tokio::task::spawn_blocking(move || {
            let mut ins = build_insights(&s, origin_of(&st2, &sha));
            ins["plain"] = plain_for(&st2, &s, &ins);
            ins["bundle"] = serde_json::to_value(bundle_of(&st2, &sha)).unwrap_or(Value::Null);
            ins["local_only"] = json!(crate::ai::local_only(&st2, &sha));
            ins
        })
        .await?,
    ))
}

/// The in-place path of a file (local mode only).
pub(crate) fn local_path(st: &Shared, sha: &str) -> Option<std::path::PathBuf> {
    if !st.local_mode {
        return None;
    }
    st.binary_location(sha).filter(|p| *p != st.blob_path(sha))
}

/// The `.app` bundle an in-place file belongs to.
pub(crate) fn bundle_of(st: &Shared, sha: &str) -> Option<crate::bundle::Bundle> {
    crate::bundle::bundle_info(&local_path(st, sha)?)
}

/// Electron code archive of the app an in-place file belongs to.
pub(crate) fn bundle_asar(st: &Shared, sha: &str) -> Option<std::path::PathBuf> {
    bundle_of(st, sha)?.asar
}

/// Plain-language report (blocking: may run `codesign -dvv`).
pub(crate) fn plain_for(st: &Shared, s: &Session, ins: &Value) -> Value {
    let path = local_path(st, &s.sha);
    let bundle = path.as_deref().and_then(crate::bundle::bundle_info);
    let cs = path
        .as_deref()
        .filter(|_| s.info.format.is_native())
        .and_then(crate::bundle::codesign_info);
    let tools = crate::tools::results_for(st, &s.sha);
    let lookups = crate::tools::lookups_for(st, &s.sha);
    crate::plain::build(crate::plain::Inputs {
        s,
        ins,
        bundle: bundle.as_ref(),
        codesign: cs.as_ref(),
        tools: &tools,
        lookups: &lookups,
    })
}

/// `GET /binaries/{sha}/trust` — full signature check of an in-place app
/// (hashes every sealed file, so it's separate from the fast overview).
pub async fn trust(State(st): State<Shared>, Path(sha): Path<String>) -> R<Json<Value>> {
    valid_sha(&sha)?;
    let Some(p) = local_path(&st, &sha) else {
        return Ok(Json(
            json!({"available": false, "reason": "Only files opened from this computer can be verified (uploads lose their signature folder)."}),
        ));
    };
    let v = tokio::task::spawn_blocking(move || {
        let info = crate::bundle::codesign_info(&p);
        if info.as_ref().is_none_or(|c| !c.signed) {
            return json!({"available": true, "signed": false});
        }
        let (valid, err) = crate::bundle::codesign_verify(&p);
        json!({"available": true, "signed": true, "valid": valid, "error": err, "info": info})
    })
    .await?;
    Ok(Json(v))
}

#[derive(Deserialize)]
pub struct DiffQ {
    other: String,
}

/// What changed from `other` (old) to `{sha}` (new).
pub async fn diff(
    State(st): State<Shared>,
    Path(sha): Path<String>,
    Query(q): Query<DiffQ>,
) -> R<Json<Value>> {
    valid_sha(&q.other)?;
    if q.other == sha {
        return Err(bad("pick a different binary to compare with"));
    }
    let new = analysed(&st, &sha).await?;
    let old = analysed(&st, &q.other).await?;
    let d = tokio::task::spawn_blocking(move || -> Result<_, String> {
        let (oi, ni) = (
            old.image.as_deref().ok_or("no image")?,
            new.image.as_deref().ok_or("no image")?,
        );
        if oi.arch != ni.arch {
            return Err(format!(
                "architectures differ ({:?} vs {:?})",
                oi.arch, ni.arch
            ));
        }
        let (oa, na) = (
            old.analysis.as_ref().ok_or("not analysed")?,
            new.analysis.as_ref().ok_or("not analysed")?,
        );
        Ok((
            drishti_disasm::diff::diff(oi, oa, ni, na),
            old.info.file_name.clone(),
            oa.functions.len(),
            na.functions.len(),
        ))
    })
    .await?
    .map_err(bad)?;
    Ok(Json(
        json!({ "diff": d.0, "old_name": d.1, "old_functions": d.2, "new_functions": d.3 }),
    ))
}

fn report_md(st: &Shared, s: &Arc<Session>, origin: Option<drishti_model::FileOrigin>) -> String {
    let i = &s.info;
    let ins = build_insights(s, origin.clone());
    let p = plain_for(st, s, &ins);
    let mut m = format!(
        "# Drishti report — {}\n\n## Verdict: {}\n\n",
        i.file_name,
        p["verdict"]["title"].as_str().unwrap_or("")
    );
    for r in p["verdict"]["reasons"].as_array().into_iter().flatten() {
        let mark = match r["tone"].as_str() {
            Some("bad") => "⛔",
            Some("warn") => "⚠️",
            Some("good") => "✅",
            _ => "•",
        };
        m += &format!("- {mark} {}\n", r["text"].as_str().unwrap_or(""));
    }
    let g = &p["grades"];
    let grades: Vec<String> = [
        ("Trust", "trust"),
        ("Security", "security"),
        ("Privacy", "privacy"),
    ]
    .iter()
    .filter_map(|(l, k)| g[k].as_str().map(|v| format!("{l} **{v}**")))
    .collect();
    if !grades.is_empty() {
        m += &format!("\nGrades: {}\n", grades.join(" · "));
    }
    m += &format!("\n{}\n\n", ins["summary"].as_str().unwrap_or(""));
    let mk = &p["maker"];
    m += &format!(
        "## Who made it\n\n**{}** ({})\n\n",
        mk["name"].as_str().unwrap_or("Unknown"),
        mk["trust"].as_str().unwrap_or("")
    );
    for d in mk["detail"].as_array().into_iter().flatten() {
        m += &format!("- {}\n", d.as_str().unwrap_or(""));
    }
    let perms = p["permissions"].as_array().cloned().unwrap_or_default();
    if !perms.is_empty() {
        m += "\n## What it can access\n\n";
        for x in &perms {
            m += &format!(
                "- **{}**{}: {}{}\n",
                x["label"].as_str().unwrap_or(""),
                if x["sensitive"] == true {
                    " (sensitive)"
                } else {
                    ""
                },
                x["why"]
                    .as_array()
                    .map(|w| w
                        .iter()
                        .filter_map(|v| v.as_str())
                        .collect::<Vec<_>>()
                        .join("; "))
                    .unwrap_or_default(),
                x["explanation"]
                    .as_str()
                    .map(|e| format!(". Developer's reason: \u{201c}{e}\u{201d}"))
                    .unwrap_or_default()
            );
        }
    }
    let sdks = p["sdks"].as_array().cloned().unwrap_or_default();
    if !sdks.is_empty() {
        m += "\n## Built-in kits from other companies\n\n";
        for k in &sdks {
            m += &format!(
                "- **{}** — {}\n",
                k["name"].as_str().unwrap_or(""),
                k["category_label"].as_str().unwrap_or("")
            );
        }
    }
    for g in p["network"]["groups"].as_array().into_iter().flatten() {
        if g["id"] == "text" {
            continue;
        }
        if g["id"] == p["network"]["groups"][0]["id"] {
            m += "\n## Web addresses inside\n\n";
        }
        let hosts: Vec<&str> = g["hosts"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|h| h.as_str())
            .take(40)
            .collect();
        m += &format!(
            "- **{}**: {}\n",
            g["label"].as_str().unwrap_or(""),
            hosts.join(", ")
        );
    }
    let checks: Vec<Value> = crate::tools::results_for(st, &s.sha)
        .into_iter()
        .chain(crate::tools::lookups_for(st, &s.sha))
        .collect();
    if !checks.is_empty() {
        m += "\n## Checks\n\n";
        for r in &checks {
            let name = r["tool"].as_str().or(r["service"].as_str()).unwrap_or("?");
            m += &format!(
                "- **{}** ({}): {}\n",
                crate::tools::def(name).map(|t| t.name).unwrap_or(name),
                r["verdict"].as_str().unwrap_or(""),
                r["headline"].as_str().unwrap_or("")
            );
        }
    }
    m += "\n## Technical details\n\n";
    m += &format!(
        "| | |\n|---|---|\n| SHA-256 | `{}` |\n| MD5 | `{}` |\n| Size | {} bytes |\n| Format | {:?} |\n| Architecture | {:?} |\n| Platform | {:?} |\n| Entropy | {:.3} |\n\n",
        i.sha256, i.md5, i.size, i.format, i.arch, i.platform, i.entropy
    );
    if let Some(a) = &s.analysis {
        m += &format!(
            "**Analysis:** {} functions, {} instructions, {} cross-references.\n\n",
            a.functions.len(),
            a.stats.instructions,
            a.xrefs.len()
        );
    }
    let list = |v: &Value| v.as_array().cloned().unwrap_or_default();
    if let Some(o) = &origin {
        m += "## Downloaded from\n\n";
        for w in &o.where_from {
            m += &format!("- {w}\n");
        }
        if let Some(a) = &o.downloaded_by {
            m += &format!("- App: {a}\n");
        }
        if let Some(t) = &o.downloaded_at {
            m += &format!("- When: {t}\n");
        }
        m += "\n";
    }
    if let Some(d) = document_of(s) {
        m += &format!("## Document safety\n\n{}\n\n", d.verdict);
        for f in &d.features {
            m += &format!(
                "- **{}** ×{} ({:?}): {}\n",
                f.name, f.count, f.severity, f.explanation
            );
        }
        m += "\n## Where it came from\n\n";
        for c in &d.clues {
            m += &format!("- {} *({:?} confidence)*\n", c.text, c.confidence);
        }
        m += "\n## Document metadata\n\n| Field | Value | Source |\n|---|---|---|\n";
        for f in &d.metadata {
            m += &format!(
                "| {} | {} | {} |\n",
                f.key,
                f.value.replace('|', "\\|"),
                f.source
            );
        }
        if !d.history.is_empty() {
            m += "\n## Edit history\n\n";
            for h in &d.history {
                m += &format!(
                    "- {} — {} {}\n",
                    h.when.as_deref().unwrap_or("?"),
                    h.action,
                    h.software.as_deref().unwrap_or("")
                );
            }
        }
        if !d.links.is_empty() {
            m += "\n## Links\n\n";
            for l in &d.links {
                m += &format!("- {l}\n");
            }
        }
        m += "\n";
    }
    if !list(&ins["hardening"]).is_empty() {
        m += "## Security hardening\n\n";
        for c in list(&ins["hardening"]) {
            let mark = match c["status"].as_str() {
                Some("good") => "✅",
                Some("bad") => "⚠️",
                _ => "ℹ️",
            };
            m += &format!(
                "- {mark} **{}** — {}\n",
                c["name"].as_str().unwrap_or(""),
                c["detail"].as_str().unwrap_or("")
            );
        }
        m += "\n";
    }
    if let Some(e) = ins["signing"]["entitlements"]
        .as_array()
        .filter(|e| !e.is_empty())
    {
        m += "## Entitlements\n\n";
        for kv in e {
            m += &format!(
                "- `{}` = {}\n",
                kv[0].as_str().unwrap_or(""),
                kv[1].as_str().unwrap_or("")
            );
        }
        m += "\n";
    }
    if !list(&ins["behaviors"]).is_empty() {
        m += "## Behaviours\n\n";
        for b in list(&ins["behaviors"]) {
            let apis: Vec<&str> = b["apis"]
                .as_array()
                .map(|a| a.iter().filter_map(|x| x.as_str()).collect())
                .unwrap_or_default();
            m += &format!(
                "- **{}** ({}) — {} APIs: `{}`. Referenced by {} function(s).\n",
                b["name"].as_str().unwrap_or(""),
                b["severity"].as_str().unwrap_or(""),
                b["description"].as_str().unwrap_or(""),
                apis.join("`, `"),
                b["function_count"]
            );
        }
        m += "\n";
    }
    if !s.findings.is_empty() {
        m += "## Findings\n\n";
        for f in &s.findings {
            m += &format!("- **{}** — {}\n", f.title, f.detail);
        }
        m += "\n";
    }
    let iocs = list(&ins["iocs"]);
    if !iocs.is_empty() {
        m += "## Indicators\n\n";
        for x in iocs.iter().take(200) {
            m += &format!(
                "- {}: `{}`\n",
                x["kind"].as_str().unwrap_or(""),
                x["value"].as_str().unwrap_or("").replace('`', "'")
            );
        }
        m += "\n";
    }
    if let Some(img) = &s.image {
        m += "## Sections\n\n| Name | Address | Size | Perms | Entropy |\n|---|---|---|---|---|\n";
        for sec in &img.sections {
            m += &format!(
                "| {} | {} | {} | {} | {:.2} |\n",
                sec.name, sec.vaddr, sec.vsize, sec.perms, sec.entropy
            );
        }
    }
    m += "\n_Generated by Drishti (static analysis; the file was never executed)._\n";
    m
}

pub async fn report(State(st): State<Shared>, Path(sha): Path<String>) -> R<Response> {
    let s = session(&st, &sha).await?;
    let name = format!(
        "{}-report.md",
        s.info.file_name.replace(['"', '/', '\\'], "_")
    );
    let st2 = st.clone();
    let body =
        tokio::task::spawn_blocking(move || report_md(&st2, &s, origin_of(&st2, &sha))).await?;
    Ok((
        [
            (
                header::CONTENT_TYPE,
                "text/markdown; charset=utf-8".to_string(),
            ),
            (
                header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"{name}\""),
            ),
        ],
        body,
    )
        .into_response())
}

/// Local mode: installed applications, for the home-screen picker.
pub async fn local_apps(State(st): State<Shared>) -> R<Json<Value>> {
    if !st.local_mode {
        return Err(ApiError(
            StatusCode::FORBIDDEN,
            "not available in server mode".into(),
        ));
    }
    let apps = tokio::task::spawn_blocking(|| {
        let mut out: Vec<(String, String)> = Vec::new();
        let home = std::env::var("HOME").unwrap_or_default();
        for dir in [
            "/Applications".to_string(),
            format!("{home}/Applications"),
            "/System/Applications".to_string(),
            "/Applications/Utilities".to_string(),
        ] {
            let Ok(rd) = std::fs::read_dir(&dir) else {
                continue;
            };
            for e in rd.flatten() {
                let p = e.path();
                if p.extension().and_then(|x| x.to_str()) == Some("app")
                    && let Some(n) = p.file_stem().and_then(|x| x.to_str())
                {
                    out.push((n.to_string(), p.to_string_lossy().into_owned()));
                }
            }
        }
        out.sort_by_key(|a| a.0.to_lowercase());
        out.dedup();
        out
    })
    .await?;
    if apps.is_empty() {
        return Err(not_found("no applications found"));
    }
    Ok(Json(
        json!({ "apps": apps.into_iter().map(|(n, p)| json!({"name": n, "path": p})).collect::<Vec<_>>() }),
    ))
}

// ---- Vulnerability audit (Feature 1 / Feature 5 analysis) -------------------

/// `GET /binaries/{sha}/vulns` — static input→sink reachability audit.
pub async fn vulns(State(st): State<Shared>, Path(sha): Path<String>) -> R<Json<Value>> {
    let s = analysed(&st, &sha).await?;
    let renames = st.renames(&sha);
    let report = tokio::task::spawn_blocking(move || {
        let img = s.image.as_deref().ok_or("not a native binary")?;
        let a = s.analysis.as_ref().ok_or("not analysed")?;
        let mut report = drishti_disasm::vuln::audit(img, a);
        // Apply user renames to every function reference.
        let rn = |fr: &mut drishti_disasm::vuln::FnRef| {
            if let Some(n) = renames.get(&fr.entry.0) {
                fr.name = n.clone();
            }
        };
        for f in &mut report.findings {
            rn(&mut f.sink_fn);
            if let Some(sf) = f.source_fn.as_mut() {
                rn(sf);
            }
            for p in &mut f.path {
                rn(p);
            }
        }
        Ok::<_, String>(report)
    })
    .await?
    .map_err(|e: String| {
        if e == "not analysed" {
            not_found("not analysed")
        } else {
            bad(e)
        }
    })?;
    Ok(Json(serde_json::to_value(report).unwrap_or(Value::Null)))
}

// ---- Natural-language function query (Feature 6) ----------------------------

#[derive(Deserialize)]
pub struct NlReq {
    pub question: String,
}

/// `POST /binaries/{sha}/nl-query` — translate a plain-English question into
/// the function query language, run it, and return the query plus the matches.
pub async fn nl_query(
    State(st): State<Shared>,
    Path(sha): Path<String>,
    Json(req): Json<NlReq>,
) -> R<Json<Value>> {
    if req.question.len() > 500 {
        return Err(bad("question too long"));
    }
    let s = analysed(&st, &sha).await?;
    let renames = st.renames(&sha);
    let out = tokio::task::spawn_blocking(move || {
        let a = s.analysis.as_ref().ok_or("not analysed")?;
        let t = drishti_disasm::nlq::heuristic(&req.question);
        if t.empty {
            return Ok::<_, String>(json!({
                "question": req.question,
                "query": "",
                "notes": [],
                "source": "heuristic",
                "understood": false,
                "hint": "Try terms like JSON, file, network, shell command, encrypt, password, complex, unused, recursive.",
                "matches": [],
                "total": 0,
            }));
        }
        let fq = drishti_disasm::search::FnQuery::parse(&t.query)
            .map_err(|e| format!("translated query `{}` did not parse: {e}", t.query))?;
        let name_of = |x: u64| renames.get(&x).cloned().or_else(|| s.base_name(x));
        let is_renamed = |x: u64| renames.contains_key(&x);
        let cx = drishti_disasm::search::FnCtx {
            analysis: a,
            image: s.image.as_deref(),
            strings: &s.strings,
            name_of: &name_of,
            is_renamed: &is_renamed,
        };
        let mut matches = Vec::new();
        let mut total = 0usize;
        for f in a.functions.iter().filter(|f| {
            fq.matches(f, renames.get(&f.entry).map(String::as_str).unwrap_or(&f.name), &cx)
        }) {
            total += 1;
            if matches.len() < 200 {
                matches.push(json!({
                    "entry": drishti_model::Addr(f.entry),
                    "name": renames.get(&f.entry).cloned().unwrap_or_else(|| f.name.to_string()),
                    "size": f.size,
                    "callers": f.called_by.len(),
                    "complexity": f.cyclomatic(),
                }));
            }
        }
        Ok(json!({
            "question": req.question,
            "query": t.query,
            "notes": t.notes,
            "source": "heuristic",
            "understood": true,
            "matches": matches,
            "total": total,
        }))
    })
    .await?
    .map_err(|e: String| if e == "not analysed" { not_found("not analysed") } else { bad(e) })?;
    Ok(Json(out))
}
