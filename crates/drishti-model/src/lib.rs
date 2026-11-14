//! Drishti normalized schema.
//!
//! These Rust types are the single source of truth for the engine-independent
//! JSON format (spec §6). `schemars` generates `schema/drishti.schema.json`
//! from them; every engine adapter, the API, the UI and the MCP server only
//! speak this format, which keeps engines swappable.
#![forbid(unsafe_code)]

use schemars::{JsonSchema, Schema, SchemaGenerator, json_schema};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::borrow::Cow;
use std::fmt;

/// Current schema version (semver). Bump major on breaking changes.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// A virtual address. Stored as `u64`, serialized as a hex string
/// (`"0x401000"`) because JavaScript numbers lose precision above 2^53.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Addr(pub u64);

impl fmt::Debug for Addr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:#x}", self.0)
    }
}
impl fmt::Display for Addr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:#x}", self.0)
    }
}
impl From<u64> for Addr {
    fn from(v: u64) -> Self {
        Addr(v)
    }
}

impl Addr {
    /// Parse `"0x401000"`, `"401000"` (hex) or a decimal with `#` prefix.
    pub fn parse(s: &str) -> Option<Addr> {
        let s = s.trim();
        if let Some(d) = s.strip_prefix('#') {
            return d.parse().ok().map(Addr);
        }
        let h = s
            .strip_prefix("0x")
            .or_else(|| s.strip_prefix("0X"))
            .unwrap_or(s);
        u64::from_str_radix(h, 16).ok().map(Addr)
    }
}

impl Serialize for Addr {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(&format_args!("{:#x}", self.0))
    }
}
impl<'de> Deserialize<'de> for Addr {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s: Cow<'de, str> = Deserialize::deserialize(d)?;
        Addr::parse(&s).ok_or_else(|| serde::de::Error::custom("invalid hex address"))
    }
}
impl JsonSchema for Addr {
    fn schema_name() -> Cow<'static, str> {
        "Addr".into()
    }
    fn json_schema(_: &mut SchemaGenerator) -> Schema {
        json_schema!({"type": "string", "pattern": "^0x[0-9a-f]+$"})
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum Format {
    Elf,
    Pe,
    PeDotnet,
    Coff,
    Macho,
    MachoFat,
    JavaClass,
    Dex,
    Apk,
    Ipa,
    Jar,
    Ooxml,
    Zip,
    Wasm,
    Ole,
    Pdf,
    /// Electron application archive (modern desktop apps).
    Asar,
    /// Unix `ar` archive (static libraries).
    Archive,
    Raw,
    Firmware,
    Unknown,
}

impl Format {
    /// Native code formats handled by the core engine.
    pub fn is_native(self) -> bool {
        matches!(
            self,
            Format::Elf
                | Format::Pe
                | Format::PeDotnet
                | Format::Macho
                | Format::MachoFat
                | Format::Coff
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Arch {
    X86,
    X86_64,
    Arm,
    Aarch64,
    Mips,
    Mips64,
    Riscv64,
    Ppc,
    Dalvik,
    Cil,
    Jvm,
    Wasm,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Endian {
    Little,
    Big,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Platform {
    Windows,
    Linux,
    Macos,
    Ios,
    Android,
    Dotnet,
    Java,
    Web,
    Embedded,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum Container {
    Zip,
    FatMacho,
    Firmware,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ChildFile {
    pub path: String,
    /// Empty when the child was listed but not extracted (e.g. over size limit).
    pub sha256: String,
    pub format: Format,
    pub size: u64,
    /// Architecture slice name for fat Mach-O children (e.g. "arm64").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub arch: Option<Arch>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct FileInfo {
    pub sha256: String,
    pub md5: String,
    pub size: u64,
    pub file_name: String,
    pub format: Format,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub container: Option<Container>,
    pub arch: Arch,
    pub bits: Option<u8>,
    pub endian: Option<Endian>,
    pub platform: Platform,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entry_point: Option<Addr>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub is_stripped: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub is_packed_suspected: Option<bool>,
    /// Overall Shannon entropy of the file, 0..8.
    pub entropy: f32,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub compiler_hints: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub libraries: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub children: Vec<ChildFile>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct Section {
    pub name: String,
    pub vaddr: Addr,
    pub vsize: u64,
    pub file_offset: u64,
    pub file_size: u64,
    /// e.g. "r-x", "rw-"
    pub perms: String,
    /// Shannon entropy of the file-backed bytes, 0..8.
    pub entropy: f32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SymbolKind {
    Function,
    Object,
    Import,
    Export,
    Label,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SymbolSource {
    Symtab,
    Dynsym,
    ExportTable,
    ImportTable,
    Pdb,
    Dwarf,
    Engine,
    User,
    Ai,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct Symbol {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub demangled: Option<String>,
    pub addr: Addr,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
    pub kind: SymbolKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub library: Option<String>,
    pub source: SymbolSource,
}

impl Symbol {
    /// Name to show users: demangled when available.
    pub fn display_name(&self) -> &str {
        self.demangled.as_deref().unwrap_or(&self.name)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum StringEncoding {
    Ascii,
    Utf16le,
    Utf8,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct StringRef {
    pub addr: Addr,
    pub value: String,
    pub encoding: StringEncoding,
    #[serde(default)]
    pub xrefs: Vec<Addr>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum InsnKind {
    Call,
    Jump,
    Cjump,
    Ret,
    Other,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct Instruction {
    pub addr: Addr,
    pub size: u32,
    /// Hex-encoded bytes.
    pub bytes: String,
    pub mnemonic: String,
    pub operands: String,
    pub kind: InsnKind,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub targets: Vec<Addr>,
    /// Resolved name of the branch/data target (import, function, string).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum EdgeKind {
    Fallthrough,
    Jump,
    True,
    False,
    Switch,
    Indirect,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct Edge {
    pub target: Addr,
    pub kind: EdgeKind,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct BasicBlock {
    pub start: Addr,
    /// Exclusive.
    pub end: Addr,
    pub instructions: Vec<Addr>,
    pub successors: Vec<Edge>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum EngineId {
    Core,
    Ghidra,
    Angr,
    Radare2,
    Rizin,
    Jadx,
    Ilspy,
    Wabt,
    Binwalk,
    Oletools,
    Yara,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum NameSource {
    Symbol,
    Engine,
    Signature,
    User,
    Ai,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct FunctionMetrics {
    pub block_count: u32,
    pub edge_count: u32,
    pub cyclomatic: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub goto_count: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub loc: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum Language {
    C,
    Java,
    Csharp,
    WasmPseudo,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct LineMap {
    pub line: u32,
    pub addrs: Vec<Addr>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct Variable {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub r#type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub storage: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct Decompilation {
    pub engine: EngineId,
    pub language: Language,
    pub code: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub line_map: Vec<LineMap>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub variables: Vec<Variable>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct Function {
    pub engine: EngineId,
    pub engine_version: String,
    pub entry: Addr,
    pub name: String,
    pub name_source: NameSource,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
    #[serde(default)]
    pub blocks: Vec<BasicBlock>,
    #[serde(default)]
    pub calls: Vec<Addr>,
    #[serde(default)]
    pub called_by: Vec<Addr>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub is_thunk: bool,
    /// Never returns to its caller (by name, or proven by propagation).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub noreturn: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub is_library: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decompiled: Option<Decompilation>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metrics: Option<FunctionMetrics>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum XrefKind {
    Call,
    Jump,
    DataRead,
    DataWrite,
    String,
    Pointer,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Xref {
    pub from: Addr,
    pub to: Addr,
    pub kind: XrefKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum FindingKind {
    Yara,
    SuspiciousApi,
    Packer,
    Macro,
    HighEntropy,
    EmbeddedFile,
    Other,
}

#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    #[default]
    Info,
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct Finding {
    pub kind: FindingKind,
    pub severity: Severity,
    pub title: String,
    pub detail: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub addrs: Vec<Addr>,
    /// Engine id or `"rule"`.
    pub source: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Ok,
    Partial,
    Failed,
    Timeout,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ErrorEntry {
    pub code: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct AnalysisResult {
    pub schema_version: String,
    pub engine: EngineId,
    pub engine_version: String,
    pub options_hash: String,
    pub started_at: String,
    pub duration_ms: u64,
    pub status: Status,
    pub file: FileInfo,
    pub sections: Vec<Section>,
    pub symbols: Vec<Symbol>,
    pub imports: Vec<Symbol>,
    pub exports: Vec<Symbol>,
    pub strings: Vec<StringRef>,
    pub functions: Vec<Function>,
    pub xrefs: Vec<Xref>,
    #[serde(default)]
    pub findings: Vec<Finding>,
    #[serde(default)]
    pub errors: Vec<ErrorEntry>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AnnotationKind {
    RenameFunction,
    RenameVariable,
    Comment,
    Type,
    Bookmark,
    Tag,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Author {
    User,
    Ai,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AiStatus {
    Verified,
    Refuted,
    Unverified,
    Accepted,
    Rejected,
}

/// User/AI edits; stored separately from immutable engine results (spec §6.3).
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct Annotation {
    pub id: String,
    pub binary_sha256: String,
    pub addr: Addr,
    pub kind: AnnotationKind,
    pub value: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    pub author: Author,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ai_status: Option<AiStatus>,
    pub created_at: String,
    pub updated_at: String,
}

// ---------------------------------------------------------------- documents

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    Low,
    Medium,
    High,
}

/// One metadata value and where in the document it was read from.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct MetaField {
    /// Human-readable key, e.g. "Producer", "Created".
    pub key: String,
    pub value: String,
    /// `info` (document information dictionary), `xmp` (XMP packet),
    /// `trailer`, or `previous` (an older revision's information dictionary).
    pub source: String,
}

/// A step from the document's recorded edit history (XMP `xmpMM:History`).
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct HistoryEvent {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub when: Option<String>,
    pub action: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub software: Option<String>,
}

/// A digital signature field.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct DocSignature {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signed_at: Option<String>,
    /// Certificate authority that issued the signer's certificate.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub location: Option<String>,
    /// Names found in the signature's certificates (signer and issuer).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub certificate_names: Vec<String>,
    /// Whether the signed byte range reaches the end of the file. `false`
    /// means the file was changed after this signature was applied.
    pub covers_whole_file: bool,
}

/// An active or risky feature (scripts, auto-actions, attachments, …).
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct DocFeature {
    pub name: String,
    pub count: u32,
    pub severity: Severity,
    pub explanation: String,
}

/// A plain-language clue about where the document came from.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct OriginClue {
    /// `made_with`, `device`, `author`, `dates`, `edited`, `signed`,
    /// `scanned`, `region`, `identity`, `downloaded`.
    pub topic: String,
    pub text: String,
    pub confidence: Confidence,
}

/// Provenance and safety triage for a document (currently PDF).
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct DocumentReport {
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pages: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub page_size: Option<String>,
    pub encrypted: bool,
    pub linearized: bool,
    /// Saved revisions (1 = written once; more = incremental updates).
    pub revisions: u32,
    pub metadata: Vec<MetaField>,
    pub history: Vec<HistoryEvent>,
    pub signatures: Vec<DocSignature>,
    pub fonts: Vec<String>,
    pub images: u32,
    pub links: Vec<String>,
    pub embedded_files: Vec<String>,
    pub features: Vec<DocFeature>,
    pub clues: Vec<OriginClue>,
    /// Highest feature severity (`info` when nothing risky was found).
    pub risk: Severity,
    /// One-sentence plain-language safety verdict.
    pub verdict: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

/// Where a file on disk came from, from macOS download metadata
/// (`kMDItemWhereFroms`, `com.apple.quarantine`). Only available for files
/// opened in place; browser uploads do not carry it.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct FileOrigin {
    /// Download URL and the page it was linked from, or a mail sender/subject.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub where_from: Vec<String>,
    /// The app that downloaded or received it (e.g. "Safari", "Mail").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub downloaded_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub downloaded_at: Option<String>,
    pub quarantined: bool,
}

/// JSON Schema for the root `AnalysisResult` document, plus `Annotation`,
/// `DocumentReport` and `FileOrigin`.
pub fn json_schema() -> serde_json::Value {
    let mut root = schemars::schema_for!(AnalysisResult).to_value();
    let extra = [
        ("Annotation", schemars::schema_for!(Annotation).to_value()),
        (
            "DocumentReport",
            schemars::schema_for!(DocumentReport).to_value(),
        ),
        ("FileOrigin", schemars::schema_for!(FileOrigin).to_value()),
    ];
    if let Some(defs) = root.get_mut("$defs").and_then(|d| d.as_object_mut()) {
        for (name, schema) in extra {
            let Some(obj) = schema.as_object() else {
                continue;
            };
            let mut a = obj.clone();
            a.remove("$schema");
            if let Some(serde_json::Value::Object(adefs)) = a.remove("$defs") {
                for (k, v) in adefs {
                    defs.entry(k).or_insert(v);
                }
            }
            defs.insert(name.into(), serde_json::Value::Object(a));
        }
    }
    root
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn addr_roundtrip() {
        let a = Addr(0x401000);
        let s = serde_json::to_string(&a).unwrap();
        assert_eq!(s, "\"0x401000\"");
        let b: Addr = serde_json::from_str(&s).unwrap();
        assert_eq!(a, b);
        assert_eq!(Addr::parse("401000"), Some(a));
        assert_eq!(Addr::parse("#16"), Some(Addr(16)));
        assert_eq!(Addr::parse("zz"), None);
    }

    #[test]
    fn format_names_match_spec() {
        assert_eq!(
            serde_json::to_string(&Format::PeDotnet).unwrap(),
            "\"pe-dotnet\""
        );
        assert_eq!(serde_json::to_string(&Arch::X86_64).unwrap(), "\"x86_64\"");
    }

    #[test]
    fn schema_generates() {
        let s = json_schema();
        assert!(s["$defs"]["Function"].is_object());
        assert!(s["$defs"]["Annotation"].is_object());
        assert!(s["$defs"]["DocumentReport"].is_object());
        assert!(s["$defs"]["FileOrigin"].is_object());
    }
}
