//! `drishti` — command-line interface (spec §7.16).

mod mcp;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use drishti_disasm::{Options, analyze};
use drishti_loader::{Image, load_image, open};
use drishti_model::{Addr, Arch};
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::time::Instant;

#[derive(Parser)]
#[command(
    name = "drishti",
    version,
    about = "Drishti — fast, local reverse-engineering toolkit"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// File triage: format, arch, hashes, sections, findings.
    Info {
        file: PathBuf,
        #[arg(long)]
        json: bool,
        /// Fat Mach-O slice (x86_64, aarch64).
        #[arg(long)]
        arch: Option<String>,
    },
    /// Extract ASCII + UTF-16LE strings.
    Strings {
        file: PathBuf,
        #[arg(long, default_value_t = 4)]
        min: usize,
        #[arg(long)]
        json: bool,
        #[arg(long, default_value_t = 1_000_000)]
        limit: usize,
    },
    /// Disassemble instructions at an address (default: entry point).
    Disasm {
        file: PathBuf,
        #[arg(long)]
        addr: Option<String>,
        #[arg(long, default_value_t = 40)]
        count: usize,
        #[arg(long)]
        arch: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// Discover functions with the core engine.
    Functions {
        file: PathBuf,
        #[arg(long)]
        json: bool,
        #[arg(long)]
        arch: Option<String>,
        #[arg(long)]
        no_gap_scan: bool,
    },
    /// Lift to the Drishti IR (AArch64): one function's IR, or `--coverage`
    /// for the share of all instructions with full semantics.
    Lift {
        file: PathBuf,
        /// Function address (hex); omit with --coverage.
        addr: Option<String>,
        #[arg(long)]
        coverage: bool,
        /// Load test: lift every function through a cache of this many MB
        /// and report the most it ever held.
        #[arg(long)]
        cache_mb: Option<usize>,
        #[arg(long)]
        json: bool,
        #[arg(long)]
        arch: Option<String>,
    },
    /// Full core analysis; writes the normalized schema JSON.
    Analyze {
        file: PathBuf,
        /// Output file (default: stdout).
        #[arg(long, short)]
        out: Option<PathBuf>,
        #[arg(long)]
        arch: Option<String>,
        /// Include per-block instruction address lists (larger output).
        #[arg(long)]
        insns: bool,
    },
    /// Engine worker contract (spec §7.7): writes DIR/normalized.json.
    Worker {
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        out: PathBuf,
        #[arg(long, default_value = "{}")]
        options: String,
    },
    /// Compare discovered function starts against symbols (benchmark).
    Bench {
        /// Binary with symbols (ground truth).
        file: PathBuf,
        /// Analyse this stripped copy instead (same layout).
        #[arg(long)]
        stripped: Option<PathBuf>,
        #[arg(long)]
        arch: Option<String>,
        /// Ignore loader seeds (entry point only).
        #[arg(long)]
        no_hints: bool,
    },
    /// Compare two versions of a binary: matched, changed, added, removed functions.
    Diff {
        old: PathBuf,
        new: PathBuf,
        #[arg(long)]
        arch: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// Search a file: text (UTF-8/UTF-16), YARA-style hex, regex over bytes,
    /// numbers, or instruction patterns (`--mode insn "mov edi, *; call *malloc"`).
    Search {
        file: PathBuf,
        query: String,
        /// text | hex | regex | number | insn
        #[arg(long, short, default_value = "text")]
        mode: String,
        /// Case-sensitive match (text, regex, insn).
        #[arg(long)]
        case: bool,
        /// Text encodings: utf8,utf16le,utf16be (default utf8,utf16le).
        #[arg(long)]
        enc: Option<String>,
        /// Number width in bits: 8, 16, 32, 64 (default: every width it fits).
        #[arg(long)]
        width: Option<u32>,
        /// Number byte order: file, le, be, both.
        #[arg(long, default_value = "file")]
        endian: String,
        /// all, code, data, or a section name (__cstring, .rdata...).
        #[arg(long, default_value = "all")]
        scope: String,
        /// Instruction mode: each `;`-separated part is a regex.
        #[arg(long)]
        regex: bool,
        #[arg(long)]
        arch: Option<String>,
        #[arg(long, default_value_t = 50)]
        limit: usize,
        #[arg(long)]
        json: bool,
    },
    /// Where a document came from and whether it is safe: PDF metadata,
    /// edit history, signatures, risky features, plus macOS download origin.
    Doc {
        file: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Start the API server + web UI.
    Serve {
        #[arg(long, default_value = "127.0.0.1")]
        host: String,
        #[arg(long, default_value_t = 7878)]
        port: u16,
        /// Data directory (blobs, results, database).
        #[arg(long)]
        data: Option<PathBuf>,
    },
    /// Run an MCP server on stdio so AI agents (e.g. Claude Code) can use Drishti.
    Mcp {
        #[arg(long)]
        data: Option<PathBuf>,
    },
    /// Print the normalized JSON Schema.
    Schema,
    /// List engines and their availability.
    Engines,
}

/// Counting allocator: `DRISHTI_MEMSTAT=1` prints peak heap use. Used to
/// keep the memory budget honest on large binaries.
mod memstat {
    use std::alloc::{GlobalAlloc, Layout, System};
    use std::sync::atomic::{AtomicBool, AtomicIsize, Ordering};
    // Signed: frees of blocks allocated before counting was switched on
    // may take it below zero.
    pub static CUR: AtomicIsize = AtomicIsize::new(0);
    pub static PEAK: AtomicIsize = AtomicIsize::new(0);
    /// Off unless `DRISHTI_MEMSTAT` is set: shared counters updated on every
    /// allocation make multi-threaded work (the server, parallel search)
    /// several times slower through cache-line contention.
    pub static ON: AtomicBool = AtomicBool::new(false);
    fn add(n: usize) {
        let c = CUR.fetch_add(n as isize, Ordering::Relaxed) + n as isize;
        if c > PEAK.load(Ordering::Relaxed) {
            PEAK.fetch_max(c, Ordering::Relaxed);
        }
    }
    pub struct Counting;
    // SAFETY: forwards to the system allocator unchanged; only counts bytes.
    unsafe impl GlobalAlloc for Counting {
        unsafe fn alloc(&self, l: Layout) -> *mut u8 {
            let p = unsafe { System.alloc(l) };
            if !p.is_null() && ON.load(Ordering::Relaxed) {
                add(l.size());
            }
            p
        }
        unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
            unsafe { System.dealloc(p, l) };
            if ON.load(Ordering::Relaxed) {
                CUR.fetch_sub(l.size() as isize, Ordering::Relaxed);
            }
        }
        unsafe fn realloc(&self, p: *mut u8, l: Layout, n: usize) -> *mut u8 {
            let q = unsafe { System.realloc(p, l, n) };
            if !q.is_null() && ON.load(Ordering::Relaxed) {
                if n > l.size() {
                    add(n - l.size());
                } else {
                    CUR.fetch_sub((l.size() - n) as isize, Ordering::Relaxed);
                }
            }
            q
        }
    }
    /// Physical footprint of this process (what Activity Monitor shows).
    /// The heap counter alone misses allocator slack and the transient
    /// old + new copy of a moved `realloc`.
    #[cfg(target_os = "macos")]
    fn footprint_mb() -> Option<u64> {
        // rusage_info_v0: 16-byte uuid followed by 10 u64 counters;
        // ri_phys_footprint is the 8th counter.
        #[repr(C)]
        struct RusageInfoV0 {
            uuid: [u8; 16],
            v: [u64; 10],
        }
        unsafe extern "C" {
            fn proc_pid_rusage(pid: i32, flavor: i32, buf: *mut RusageInfoV0) -> i32;
        }
        let mut r = RusageInfoV0 {
            uuid: [0; 16],
            v: [0; 10],
        };
        // SAFETY: libproc fills a caller-owned rusage_info_v0 (flavor 0).
        let rc = unsafe { proc_pid_rusage(std::process::id() as i32, 0, &mut r) };
        (rc == 0).then_some(r.v[7] >> 20)
    }
    #[cfg(not(target_os = "macos"))]
    fn footprint_mb() -> Option<u64> {
        None
    }

    pub fn report(stage: &str) {
        if std::env::var_os("DRISHTI_MEMSTAT").is_some() {
            let fp = footprint_mb()
                .map(|m| format!(", footprint {m} MB"))
                .unwrap_or_default();
            eprintln!(
                "[mem] {stage}: current {} MB, peak {} MB{fp}",
                CUR.load(Ordering::Relaxed).max(0) >> 20,
                PEAK.load(Ordering::Relaxed) >> 20
            );
        }
    }
}

#[global_allocator]
static ALLOC: memstat::Counting = memstat::Counting;

fn parse_arch(s: &Option<String>) -> Result<Option<Arch>> {
    Ok(match s.as_deref() {
        None => None,
        Some("x86_64" | "x64" | "amd64") => Some(Arch::X86_64),
        Some("aarch64" | "arm64" | "arm64e") => Some(Arch::Aarch64),
        Some("x86" | "i386") => Some(Arch::X86),
        Some(o) => bail!("unknown arch {o}"),
    })
}

fn file_name(p: &Path) -> String {
    p.file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default()
}

fn load(
    p: &Path,
    arch: &Option<String>,
) -> Result<(std::sync::Arc<drishti_loader::Blob>, Option<Image>)> {
    let blob = open(p).with_context(|| format!("opening {}", p.display()))?;
    let img = match load_image(blob.clone(), parse_arch(arch)?) {
        Ok(i) => Some(i),
        Err(drishti_loader::LoadError::Unsupported(_)) => None,
        Err(e) => return Err(e.into()),
    };
    Ok((blob, img))
}

fn now_rfc3339() -> String {
    let d = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    drishti_server::util::rfc3339(d.as_secs())
}

fn main() -> Result<()> {
    if std::env::var_os("DRISHTI_MEMSTAT").is_some() {
        memstat::ON.store(true, std::sync::atomic::Ordering::Relaxed);
    }
    let cli = Cli::parse();
    let no_cancel = AtomicBool::new(false);
    match cli.cmd {
        Cmd::Doc { file, json } => {
            let blob = open(&file)?;
            let bytes: &[u8] = blob.as_ref().as_ref();
            let report = (drishti_loader::detect(bytes).format == drishti_model::Format::Pdf)
                .then(|| drishti_loader::pdf::analyze(bytes));
            let origin = drishti_server::origin::file_origin(&file);
            if json {
                let v = serde_json::json!({"document": report, "origin": origin});
                println!("{}", serde_json::to_string_pretty(&v)?);
                return Ok(());
            }
            if let Some(o) = &origin {
                println!("Downloaded");
                for w in &o.where_from {
                    println!("  from      {w}");
                }
                if let Some(a) = &o.downloaded_by {
                    println!("  by        {a}");
                }
                if let Some(t) = &o.downloaded_at {
                    println!("  at        {t}");
                }
            }
            let Some(r) = report else {
                if origin.is_none() {
                    println!("Not a PDF, and no download origin recorded.");
                }
                return Ok(());
            };
            println!(
                "PDF {} · {} page(s) · {} revision(s){}{}",
                r.version.as_deref().unwrap_or("?"),
                r.pages.map(|p| p.to_string()).unwrap_or("?".into()),
                r.revisions,
                r.page_size
                    .as_deref()
                    .map(|s| format!(" · {s}"))
                    .unwrap_or_default(),
                if r.encrypted { " · encrypted" } else { "" }
            );
            println!("\nSafety: {}", r.verdict);
            for f in &r.features {
                println!(
                    "  [{:?}] {} ×{}: {}",
                    f.severity, f.name, f.count, f.explanation
                );
            }
            println!("\nWhere it came from");
            for c in &r.clues {
                println!("  ({:?}) {}", c.confidence, c.text);
            }
            println!("\nMetadata");
            for m in &r.metadata {
                println!("  {:<26} {}  [{}]", m.key, m.value, m.source);
            }
            for h in &r.history {
                println!(
                    "  history: {} {} {}",
                    h.when.as_deref().unwrap_or(""),
                    h.action,
                    h.software.as_deref().unwrap_or("")
                );
            }
            if !r.links.is_empty() {
                println!("\nLinks ({})", r.links.len());
                for l in r.links.iter().take(20) {
                    println!("  {l}");
                }
            }
            for w in &r.warnings {
                println!("warning: {w}");
            }
        }
        Cmd::Info { file, json, arch } => {
            let (blob, img) = load(&file, &arch)?;
            let fi = drishti_loader::file_info(&blob, &file_name(&file), img.as_ref());
            if json {
                let findings = img
                    .as_ref()
                    .map(drishti_loader::triage::findings)
                    .unwrap_or_default();
                let v = serde_json::json!({"file": fi, "sections": img.as_ref().map(|i| &i.sections), "findings": findings,
                    "imports": img.as_ref().map(|i| i.imports.len()), "exports": img.as_ref().map(|i| i.exports.len())});
                println!("{}", serde_json::to_string_pretty(&v)?);
                return Ok(());
            }
            println!("File      {}", fi.file_name);
            println!("Size      {} bytes", fi.size);
            println!("SHA-256   {}", fi.sha256);
            println!("MD5       {}", fi.md5);
            println!("Format    {:?}", fi.format);
            println!(
                "Arch      {:?} {}",
                fi.arch,
                fi.bits.map(|b| format!("{b}-bit")).unwrap_or_default()
            );
            println!("Platform  {:?}", fi.platform);
            if let Some(e) = fi.entry_point {
                println!("Entry     {e}");
            }
            println!("Entropy   {:.3}", fi.entropy);
            if let Some(s) = fi.is_stripped {
                println!("Stripped  {s}");
            }
            if let Some(p) = fi.is_packed_suspected {
                println!("Packed?   {p}");
            }
            if !fi.compiler_hints.is_empty() {
                println!("Hints     {}", fi.compiler_hints.join(", "));
            }
            if let Some(img) = &img {
                println!(
                    "Imports   {}  Exports {}  Symbols {}  Libraries {}",
                    img.imports.len(),
                    img.exports.len(),
                    img.symbols.len(),
                    img.libraries.len()
                );
                println!("\nSections:");
                for s in &img.sections {
                    println!(
                        "  {:<28} {:>18} {:>10} {} {:.2}",
                        s.name,
                        s.vaddr.to_string(),
                        s.vsize,
                        s.perms,
                        s.entropy
                    );
                }
                let f = drishti_loader::triage::findings(img);
                if !f.is_empty() {
                    println!("\nFindings:");
                    for x in f {
                        println!("  [{:?}] {} — {}", x.severity, x.title, x.detail);
                    }
                }
                for w in &img.warnings {
                    println!("warning: {w}");
                }
            }
            if !fi.children.is_empty() {
                println!("\nChildren ({}):", fi.children.len());
                for c in fi.children.iter().take(50) {
                    println!("  {:?} {:>10} {}", c.format, c.size, c.path);
                }
            }
        }
        Cmd::Strings {
            file,
            min,
            json,
            limit,
        } => {
            let (blob, img) = load(&file, &None)?;
            let s = drishti_loader::strings(&blob, img.as_ref(), min, limit);
            if json {
                println!("{}", serde_json::to_string(&s)?);
            } else {
                use std::io::Write;
                let mut out = std::io::BufWriter::new(std::io::stdout().lock());
                for x in s {
                    let _ = writeln!(out, "{} {:?} {}", x.addr, x.encoding, x.value);
                }
            }
        }
        Cmd::Disasm {
            file,
            addr,
            count,
            arch,
            json,
        } => {
            let (_blob, img) = load(&file, &arch)?;
            let img = img.context("not a native binary")?;
            let a = match addr {
                Some(s) => Addr::parse(&s).context("bad address")?.0,
                None => img
                    .entry
                    .or(img.code.first().map(|c| c.start))
                    .context("no entry point")?,
            };
            let syms: std::collections::HashMap<u64, String> = img
                .symbols
                .iter()
                .map(|s| (s.addr.0, s.display_name().to_string()))
                .collect();
            let namer = |t: u64| {
                syms.get(&t)
                    .cloned()
                    .or_else(|| img.import_at(t).map(|s| s.display_name().to_string()))
            };
            let ins = drishti_disasm::disasm(&img, a, count, &namer);
            if json {
                println!("{}", serde_json::to_string_pretty(&ins)?);
            } else {
                for i in ins {
                    let c = i.comment.map(|c| format!("  ; {c}")).unwrap_or_default();
                    println!(
                        "{:>14}  {:<20} {:<8} {}{}",
                        i.addr.to_string(),
                        i.bytes,
                        i.mnemonic,
                        i.operands,
                        c
                    );
                }
            }
        }
        Cmd::Lift {
            file,
            addr,
            coverage,
            cache_mb,
            json,
            arch,
        } => {
            let (_blob, img) = load(&file, &arch)?;
            let img = img.context("not a native binary")?;
            if !drishti_disasm::lift::supported(&img) {
                anyhow::bail!("no lifter for {:?} yet (AArch64 only)", img.arch);
            }
            let t = Instant::now();
            let a = analyze(&img, &Options::default(), &|_| {}, &no_cancel)?;
            let analysed_ms = t.elapsed().as_millis();
            memstat::report("analysed");
            if let Some(mb) = cache_mb {
                let t = Instant::now();
                let mut c: drishti_disasm::lift::LiftCache =
                    drishti_disasm::lift::LiftCache::new(mb << 20);
                let (mut peak, mut ops, mut over) = (0usize, 0usize, 0u64);
                // Twice over, so the second pass is all evictions and hits.
                for _ in 0..2 {
                    for f in &a.functions {
                        if let Some(l) = c.get_or_lift(f.entry, &img, &a, f.entry) {
                            ops += l.insns.len();
                        }
                        peak = peak.max(c.used_bytes());
                        if c.used_bytes() > c.cap_bytes() {
                            over += 1;
                        }
                    }
                }
                memstat::report("lifted through cache");
                println!(
                    "cache cap {} MB: peak held {:.1} MB, {} functions cached at the end, {} IR ops produced, over-cap events {over}, {} ms",
                    mb,
                    peak as f64 / 1048576.0,
                    c.len(),
                    ops,
                    t.elapsed().as_millis()
                );
                return Ok(());
            }
            if coverage {
                let t = Instant::now();
                let cov = drishti_disasm::lift::coverage(&img, &a).context("no lifter")?;
                memstat::report("lifted");
                if json {
                    println!("{}", serde_json::to_string_pretty(&cov)?);
                } else {
                    println!(
                        "{:.2}% lifted: {} of {} instructions in {} functions (analysis {} ms, lifting {} ms)",
                        cov.percent(),
                        cov.lifted,
                        cov.instructions,
                        cov.functions,
                        analysed_ms,
                        t.elapsed().as_millis()
                    );
                    println!("unlifted by class:");
                    for (k, v) in &cov.by_class {
                        let ex: Vec<String> = cov
                            .samples
                            .get(k)
                            .map(|s| s.iter().map(|(a, w)| format!("{w:08x}@{a:x}")).collect())
                            .unwrap_or_default();
                        println!(
                            "  {k:<18} {v:>10}  {:>5.2}%  e.g. {}",
                            100.0 * *v as f64 / cov.instructions.max(1) as f64,
                            ex.join(" ")
                        );
                    }
                    println!("most common unlifted:");
                    for (m, n) in &cov.top_unlifted {
                        println!("  {m:<18} {n:>10}");
                    }
                }
            } else {
                let at = addr
                    .as_deref()
                    .and_then(Addr::parse)
                    .context("pass a function address or --coverage")?;
                let entry = a.function_containing(at.0).map_or(at.0, |f| f.entry);
                let f = drishti_disasm::lift::lift_function(&img, &a, entry)
                    .context("no function at that address")?;
                if json {
                    println!("{}", serde_json::to_string(&f.insns)?);
                } else {
                    print!("{}", drishti_ir::render(&f.insns));
                    eprintln!(
                        "{} of {} instructions lifted, {} IR ops",
                        f.lifted,
                        f.machine,
                        f.insns.len()
                    );
                }
            }
        }
        Cmd::Functions {
            file,
            json,
            arch,
            no_gap_scan,
        } => {
            let (_blob, img) = load(&file, &arch)?;
            let img = img.context("not a native binary")?;
            let t = Instant::now();
            let opts = Options {
                gap_scan: !no_gap_scan,
                ..Default::default()
            };
            memstat::report("loaded");
            let a = analyze(
                &img,
                &opts,
                &|p| {
                    if p.phase != "functions" {
                        memstat::report(p.phase)
                    }
                },
                &no_cancel,
            )?;
            memstat::report("analysed");
            if json {
                let v: Vec<_> = a
                    .functions
                    .iter()
                    .map(|f| {
                        drishti_disasm::to_model(&img, &a, f, drishti_disasm::ENGINE_VERSION, false)
                    })
                    .collect();
                println!("{}", serde_json::to_string(&v)?);
            } else {
                for f in &a.functions {
                    println!(
                        "{:>14}  {:>8}  {:>5} blk  {}{}{}",
                        Addr(f.entry).to_string(),
                        f.size,
                        f.nblocks,
                        f.name,
                        if f.is_thunk { "  [thunk]" } else { "" },
                        if f.noreturn { "  [noreturn]" } else { "" }
                    );
                }
                eprintln!(
                    "{} functions ({} seeds), {} instructions, {} jump tables, {} via gap scan, {} xrefs in {:.2?}",
                    a.functions.len(),
                    a.stats.seeds,
                    a.stats.instructions,
                    a.stats.jump_tables,
                    a.stats.gap_functions,
                    a.xrefs.len(),
                    t.elapsed()
                );
            }
        }
        Cmd::Analyze {
            file,
            out,
            arch,
            insns,
        } => {
            let started = now_rfc3339();
            let t = Instant::now();
            let (blob, img) = load(&file, &arch)?;
            let mut errors = Vec::new();
            let analysis = match &img {
                Some(i) => match analyze(i, &Options::default(), &|_| {}, &no_cancel) {
                    Ok(a) => Some(a),
                    Err(e) => {
                        errors.push(drishti_model::ErrorEntry {
                            code: "analysis".into(),
                            message: e.to_string(),
                        });
                        None
                    }
                },
                None => None,
            };
            let strings = drishti_loader::strings(&blob, img.as_ref(), 4, 200_000);
            let res = drishti_disasm::normalize::build(drishti_disasm::normalize::Inputs {
                blob: &blob,
                file_name: &file_name(&file),
                image: img.as_ref(),
                analysis: analysis.as_ref(),
                strings,
                options_hash: "default".into(),
                started_at: started,
                duration_ms: t.elapsed().as_millis() as u64,
                errors,
                with_insns: insns,
            });
            match out {
                Some(p) => {
                    let f = std::io::BufWriter::new(std::fs::File::create(&p)?);
                    serde_json::to_writer(f, &res)?;
                    eprintln!(
                        "wrote {} ({} functions) in {:.2?}",
                        p.display(),
                        res.functions.len(),
                        t.elapsed()
                    );
                }
                None => println!("{}", serde_json::to_string(&res)?),
            }
        }
        Cmd::Worker {
            input,
            out,
            options,
        } => {
            let opts: serde_json::Value =
                serde_json::from_str(&options).context("--options must be JSON")?;
            std::fs::create_dir_all(&out)?;
            let arch = opts
                .get("arch")
                .and_then(|v| v.as_str())
                .map(str::to_string);
            let started = now_rfc3339();
            let t = Instant::now();
            let (blob, img) = load(&input, &arch)?;
            let analysis = img
                .as_ref()
                .and_then(|i| analyze(i, &Options::default(), &|_| {}, &no_cancel).ok());
            let strings = drishti_loader::strings(&blob, img.as_ref(), 4, 200_000);
            let res = drishti_disasm::normalize::build(drishti_disasm::normalize::Inputs {
                blob: &blob,
                file_name: &file_name(&input),
                image: img.as_ref(),
                analysis: analysis.as_ref(),
                strings,
                options_hash: drishti_server::util::short_hash(options.as_bytes()),
                started_at: started,
                duration_ms: t.elapsed().as_millis() as u64,
                errors: vec![],
                with_insns: true,
            });
            let f = std::io::BufWriter::new(std::fs::File::create(out.join("normalized.json"))?);
            serde_json::to_writer(f, &res)?;
        }
        Cmd::Bench {
            file,
            stripped,
            arch,
            no_hints,
        } => {
            let (_b, truth_img) = load(&file, &arch)?;
            let truth_img = truth_img.context("not native")?;
            let truth: std::collections::BTreeSet<u64> = truth_img
                .symbols
                .iter()
                .filter(|s| {
                    s.kind == drishti_model::SymbolKind::Function
                        && truth_img.is_code(s.addr.0)
                        && truth_img.code_range(s.addr.0).is_none_or(|c| !c.is_stub)
                })
                .map(|s| s.addr.0)
                .collect();
            let target = stripped.unwrap_or(file);
            let (_b2, img) = load(&target, &arch)?;
            let img = img.context("not native")?;
            let a = analyze(
                &img,
                &Options {
                    use_hints: !no_hints,
                    ..Default::default()
                },
                &|_| {},
                &no_cancel,
            )?;
            println!(
                "jump tables: {}, gap-scan functions: {}",
                a.stats.jump_tables, a.stats.gap_functions
            );
            let found: std::collections::BTreeSet<u64> = a
                .functions
                .iter()
                .filter(|f| img.code_range(f.entry).is_none_or(|c| !c.is_stub))
                .map(|f| f.entry)
                .collect();
            let tp = found.intersection(&truth).count() as f64;
            let p = if found.is_empty() {
                0.0
            } else {
                tp / found.len() as f64
            };
            let r = if truth.is_empty() {
                0.0
            } else {
                tp / truth.len() as f64
            };
            println!(
                "truth={} found={} tp={} precision={:.2}% recall={:.2}%",
                truth.len(),
                found.len(),
                tp,
                p * 100.0,
                r * 100.0
            );
            for m in truth.difference(&found).take(10) {
                println!(
                    "  missed {:#x} {}",
                    m,
                    truth_img
                        .symbols
                        .iter()
                        .find(|s| s.addr.0 == *m)
                        .map(|s| s.name.as_str())
                        .unwrap_or("")
                );
            }
        }
        Cmd::Search {
            file,
            query,
            mode,
            case,
            enc,
            width,
            endian,
            scope,
            regex,
            arch,
            limit,
            json,
        } => {
            use drishti_disasm::search::{self as eng, ByteQuery, Enc, InsnPattern, Limits, Order};
            let t = Instant::now();
            let (blob, img) = load(&file, &arch)?;
            let lim = |n| Limits::new(n, std::time::Duration::from_secs(60));
            if matches!(mode.as_str(), "insn" | "code" | "instructions") {
                let img = img.context("instruction search needs a native binary")?;
                let pat = InsnPattern::compile(&query, regex, case).map_err(anyhow::Error::msg)?;
                let a = analyze(&img, &Options::default(), &|_| {}, &no_cancel)?;
                let syms: std::collections::HashMap<u64, String> = img
                    .symbols
                    .iter()
                    .map(|s| (s.addr.0, s.display_name().to_string()))
                    .collect();
                let namer = |x: u64| {
                    a.function_at(x)
                        .map(|f| f.name.to_string())
                        .or_else(|| syms.get(&x).cloned())
                        .or_else(|| img.import_at(x).map(|s| s.display_name().to_string()))
                };
                let out = eng::search_insns(&img, &a, &namer, &pat, None, lim(20_000));
                if json {
                    let hits: Vec<_> = out
                        .hits
                        .iter()
                        .take(limit)
                        .map(|h| serde_json::json!({"va": Addr(h.addr), "function": Addr(h.function), "lines": h.lines}))
                        .collect();
                    println!(
                        "{}",
                        serde_json::json!({"total": out.total, "capped": out.capped, "partial": out.timed_out, "hits": hits})
                    );
                } else {
                    for h in out.hits.iter().take(limit) {
                        let f = a
                            .function_at(h.function)
                            .map(|f| f.name.to_string())
                            .unwrap_or_default();
                        println!("{}  {:<28} {}", Addr(h.addr), f, h.lines.join(" | "));
                    }
                    eprintln!(
                        "{}{} matches · {} functions, {} instructions · {:.2?}",
                        out.total,
                        if out.capped || out.timed_out { "+" } else { "" },
                        out.functions_scanned,
                        out.instructions_scanned,
                        t.elapsed()
                    );
                }
                return Ok(());
            }
            let m = eng::Mode::parse(&mode).with_context(|| {
                format!("unknown mode `{mode}` (text, hex, regex, number, insn)")
            })?;
            let mut q = ByteQuery::new(m, query);
            q.case_sensitive = case;
            if let Some(e) = enc {
                q.encodings = Enc::parse_list(&e).map_err(anyhow::Error::msg)?;
            }
            q.width = match width {
                None => None,
                Some(8) => Some(1),
                Some(16) => Some(2),
                Some(32) => Some(4),
                Some(64) => Some(8),
                Some(w) => anyhow::bail!("--width {w} must be 8, 16, 32 or 64"),
            };
            q.endian = match endian.as_str() {
                "le" | "little" => Some(Order::Little),
                "be" | "big" => Some(Order::Big),
                "both" => None,
                _ if img
                    .as_ref()
                    .is_some_and(|i| i.endian == drishti_model::Endian::Big) =>
                {
                    Some(Order::Big)
                }
                _ => Some(Order::Little),
            };
            let c = eng::compile(&q).map_err(anyhow::Error::msg)?;
            let data = blob.as_ref().as_ref();
            let ranges = eng::scope_ranges(data.len(), img.as_ref(), &eng::Scope::parse(&scope))
                .map_err(anyhow::Error::msg)?;
            let out = eng::scan(data, &ranges, &c, lim(1_000_000));
            let va_of = |off: usize| {
                let im = img.as_ref()?;
                im.offset_to_va(off.checked_sub(im.slice_offset)? as u64)
            };
            if json {
                let hits: Vec<_> = out
                    .hits
                    .iter()
                    .take(limit)
                    .map(|h| {
                        serde_json::json!({"offset": h.offset, "len": h.len, "va": va_of(h.offset).map(Addr),
                            "label": h.label, "text": eng::match_text(data, h)})
                    })
                    .collect();
                println!(
                    "{}",
                    serde_json::json!({"total": out.total, "capped": out.capped, "partial": out.timed_out, "hits": hits})
                );
            } else {
                for h in out.hits.iter().take(limit) {
                    let va = va_of(h.offset);
                    let sect = va
                        .and_then(|v| img.as_ref()?.section_name(v))
                        .unwrap_or("-");
                    println!(
                        "{:#010x}  {:>18}  {:<16} {:<9} {:?}",
                        h.offset,
                        va.map(|v| Addr(v).to_string())
                            .unwrap_or_else(|| "-".into()),
                        sect,
                        h.label,
                        eng::match_text(data, h)
                            .chars()
                            .take(100)
                            .collect::<String>()
                    );
                }
                eprintln!(
                    "{}{} matches in {} bytes · {:.2?}",
                    out.total,
                    if out.capped || out.timed_out { "+" } else { "" },
                    ranges.iter().map(|r| r.1 - r.0).sum::<usize>(),
                    t.elapsed()
                );
            }
        }
        Cmd::Diff {
            old,
            new,
            arch,
            json,
        } => {
            let t = Instant::now();
            let (_b1, i1) = load(&old, &arch)?;
            let i1 = i1.context("old file is not a native binary")?;
            let a1 = analyze(&i1, &Options::default(), &|_| {}, &no_cancel)?;
            let (_b2, i2) = load(&new, &arch)?;
            let i2 = i2.context("new file is not a native binary")?;
            let a2 = analyze(&i2, &Options::default(), &|_| {}, &no_cancel)?;
            let ta = t.elapsed();
            memstat::report("analysed both");
            let d = drishti_disasm::diff::diff(&i1, &a1, &i2, &a2);
            memstat::report("diffed");
            if json {
                println!("{}", serde_json::to_string(&d)?);
            } else {
                let show = |title: &str, v: &[drishti_disasm::diff::DiffFn]| {
                    println!("{title} ({}):", v.len());
                    for f in v.iter().take(50) {
                        let at = |a: Option<Addr>| a.map(|a| a.to_string()).unwrap_or("-".into());
                        println!(
                            "  {:>14} → {:<14} {:>7} → {:<7} {}",
                            at(f.old),
                            at(f.new),
                            f.old_size,
                            f.new_size,
                            f.name
                        );
                    }
                };
                show("changed", &d.changed);
                show("added", &d.added);
                show("removed", &d.removed);
            }
            eprintln!(
                "{} → {} functions: {} unchanged, {} changed, {} added, {} removed{} (analysis {:.2?}, diff {:.2?})",
                a1.functions.len(),
                a2.functions.len(),
                d.unchanged,
                d.changed.len(),
                d.added.len(),
                d.removed.len(),
                if d.truncated {
                    " (lists truncated)"
                } else {
                    ""
                },
                ta,
                t.elapsed() - ta
            );
        }
        Cmd::Serve { host, port, data } => {
            let data = data.unwrap_or_else(drishti_server::default_data_dir);
            drishti_server::run(drishti_server::Config {
                host,
                port,
                data_dir: data,
            })?;
        }
        Cmd::Mcp { data } => mcp::run(&data.unwrap_or_else(drishti_server::default_data_dir))?,
        Cmd::Schema => println!(
            "{}",
            serde_json::to_string_pretty(&drishti_model::json_schema())?
        ),
        Cmd::Engines => {
            for e in drishti_server::engines::detect() {
                println!(
                    "{:<10} {:<10} {}",
                    e.name,
                    if e.available { "available" } else { "missing" },
                    if e.available {
                        e.version.or(e.path).unwrap_or_default()
                    } else {
                        format!("install: {}", e.install)
                    }
                );
            }
        }
    }
    Ok(())
}
