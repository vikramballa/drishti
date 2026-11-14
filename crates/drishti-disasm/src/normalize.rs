//! Build the normalized `AnalysisResult` document (spec §6) for the core engine.

use crate::analyze::Analysis;
use crate::render::to_model;
use drishti_loader::{Blob, Image};
use drishti_model::*;

/// Attach string xrefs from the analysis (data references that land on a
/// string's address) and return the strings sorted by address.
pub fn attach_string_xrefs(strings: &mut [StringRef], analysis: &Analysis) {
    strings.sort_by_key(|s| s.addr);
    for s in strings.iter_mut() {
        let xs = analysis.xrefs_to(s.addr.0);
        s.xrefs = xs
            .iter()
            .filter(|x| x.kind == XrefKind::DataRead)
            .map(|x| Addr(x.from))
            .collect();
    }
}

pub struct Inputs<'a> {
    pub blob: &'a Blob,
    pub file_name: &'a str,
    pub image: Option<&'a Image>,
    pub analysis: Option<&'a Analysis>,
    pub strings: Vec<StringRef>,
    pub options_hash: String,
    pub started_at: String,
    pub duration_ms: u64,
    pub errors: Vec<ErrorEntry>,
    pub with_insns: bool,
}

pub fn build(inp: Inputs<'_>) -> AnalysisResult {
    let file = drishti_loader::file_info(inp.blob, inp.file_name, inp.image);
    let mut res = AnalysisResult {
        schema_version: SCHEMA_VERSION.to_string(),
        engine: EngineId::Core,
        engine_version: crate::ENGINE_VERSION.to_string(),
        options_hash: inp.options_hash,
        started_at: inp.started_at,
        duration_ms: inp.duration_ms,
        status: if inp.errors.is_empty() {
            Status::Ok
        } else {
            Status::Partial
        },
        file,
        sections: Vec::new(),
        symbols: Vec::new(),
        imports: Vec::new(),
        exports: Vec::new(),
        strings: inp.strings,
        functions: Vec::new(),
        xrefs: Vec::new(),
        findings: Vec::new(),
        errors: inp.errors,
    };
    if let Some(img) = inp.image {
        res.sections = img.sections.clone();
        res.symbols = img.symbols.clone();
        res.imports = img.imports.clone();
        res.exports = img.exports.clone();
        res.findings = drishti_loader::triage::findings(img);
        if let Some(a) = inp.analysis {
            res.functions = a
                .functions
                .iter()
                .map(|f| to_model(img, a, f, crate::ENGINE_VERSION, inp.with_insns))
                .collect();
            res.xrefs = a
                .xrefs
                .iter()
                .map(|x| Xref {
                    from: Addr(x.from),
                    to: Addr(x.to),
                    kind: x.kind,
                })
                .collect();
            attach_string_xrefs(&mut res.strings, a);
        }
    }
    res
}
