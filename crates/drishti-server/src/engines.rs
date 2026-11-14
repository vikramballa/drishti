//! Engine registry for `drishti engines` and `GET /engines`: the built-in
//! core engine plus the optional external tools (see `tools.rs`).

use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct EngineInfo {
    pub name: &'static str,
    pub available: bool,
    pub version: Option<String>,
    pub path: Option<String>,
    pub what: &'static str,
    pub install: &'static str,
}

/// Detect engines without executing anything.
pub fn detect() -> Vec<EngineInfo> {
    let mut v = vec![EngineInfo {
        name: "core",
        available: true,
        version: Some(drishti_disasm::ENGINE_VERSION.into()),
        path: None,
        what: "Built-in Rust engine: formats, functions, flow graphs, strings, insights.",
        install: "",
    }];
    for t in crate::tools::TOOLS {
        let p = crate::tools::locate(t);
        v.push(EngineInfo {
            name: t.id,
            available: p.is_some(),
            version: None,
            path: p.map(|p| p.display().to_string()),
            what: t.what,
            install: t.install,
        });
    }
    v
}
