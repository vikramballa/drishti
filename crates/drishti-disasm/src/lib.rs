//! Drishti core disassembler: decoders, function discovery, CFG (spec §7.3).
#![forbid(unsafe_code)]

pub mod analyze;
pub mod arch;
pub mod cache;
pub mod diff;
pub mod insights;
pub mod lift;
pub mod nlq;
pub mod normalize;
pub mod render;
pub mod search;
pub mod vuln;
pub mod xrefs;

pub use analyze::{
    Analysis, AnalyzeError, Block, Func, Options, Progress, XrefC, analyze, is_noreturn_name,
};
pub use render::{disasm, to_model};
pub use xrefs::{XrefTable, Xrefs};

/// Engine version recorded in results; bump when analysis output changes.
pub const ENGINE_VERSION: &str = concat!("core-", env!("CARGO_PKG_VERSION"));
