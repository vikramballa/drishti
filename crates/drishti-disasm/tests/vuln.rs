//! Vulnerability auditor tests (source → sink reachability).
mod common;

use common::{TempDir, archs, build, have_clang, load, run};
use std::path::PathBuf;

/// Reads untrusted input, then copies it with `strcpy` and runs it with
/// `system` through a non-inlined helper: a clear input → dangerous-sink path.
const FIXTURE: &str = r#"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
__attribute__((noinline)) void handle(const char *in) {
    char cmd[64];
    strcpy(cmd, in);
    system(cmd);
}
int main(void) {
    char buf[256];
    long n = read(0, buf, sizeof buf - 1);
    if (n <= 0) return 1;
    buf[n] = 0;
    handle(buf);
    return 0;
}
"#;

fn build_fixture(dir: &TempDir, arch: &str) -> Option<PathBuf> {
    let src = dir.0.join("vulnfix.c");
    std::fs::write(&src, FIXTURE).ok()?;
    let out = dir.0.join(format!("vulnfix-{arch}"));
    build(&src, &out, "-O0", arch).then_some(out)
}

#[test]
fn finds_input_to_sink_path() {
    if !have_clang() {
        eprintln!("skip: clang not available");
        return;
    }
    let dir = TempDir::new("vuln");
    for &arch in archs() {
        let Some(path) = build_fixture(&dir, arch) else {
            continue;
        };
        let img = load(&path);
        let analysis = run(&img);
        let report = drishti_disasm::vuln::audit(&img, &analysis);

        assert!(report.sources_found >= 1, "{arch}: no sources found");
        let classes: Vec<_> = report.findings.iter().map(|f| f.class).collect();
        assert!(
            classes.contains(&"command-injection"),
            "{arch}: expected a command-injection finding, got {classes:?}"
        );
        assert!(
            classes.contains(&"buffer-overflow"),
            "{arch}: expected a buffer-overflow finding, got {classes:?}"
        );

        // `system` should be connected to the `read` source (same fn or a path).
        let sys = report
            .findings
            .iter()
            .find(|f| f.sink_api.contains("system"))
            .expect("system finding");
        assert!(
            sys.source_fn.is_some(),
            "{arch}: system sink not connected to any input source"
        );
        assert!(
            sys.confidence == "high" || sys.confidence == "medium",
            "{arch}: expected system reachable from input, got confidence {}",
            sys.confidence
        );
    }
}

#[test]
fn clean_program_has_no_high_findings() {
    if !have_clang() {
        return;
    }
    let dir = TempDir::new("vuln-clean");
    let src = dir.0.join("clean.c");
    std::fs::write(
        &src,
        r#"#include <stdio.h>
int add(int a, int b) { return a + b; }
int main(void) { printf("%d\n", add(2, 3)); return 0; }
"#,
    )
    .unwrap();
    for &arch in archs() {
        let out = dir.0.join(format!("clean-{arch}"));
        if !build(&src, &out, "-O0", arch) {
            continue;
        }
        let img = load(&out);
        let analysis = run(&img);
        let report = drishti_disasm::vuln::audit(&img, &analysis);
        // A constant-format printf with no untrusted input must not be a "high".
        assert!(
            report.findings.iter().all(|f| f.severity != "high"),
            "{arch}: clean program produced a high finding: {:?}",
            report.findings.iter().map(|f| &f.title).collect::<Vec<_>>()
        );
    }
}
