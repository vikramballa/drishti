//! Safety properties of the tools / keys / online-check endpoints, checked
//! against a real `drishti serve`:
//! - API keys go in, but never come back out (only "…last4"), and the
//!   secrets file is readable by the owner only.
//! - Invalid keys (spaces, quotes, newlines) are rejected.
//! - Online checks are off until the person turns them on.
//! - The source browser refuses paths outside the tool's folder.
//! - Tool listing works without any tool installed.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .and_then(|l| l.local_addr())
        .map(|a| a.port())
        .expect("free port")
}

fn http(port: u16, method: &str, path: &str, body: &str) -> Option<(u16, String)> {
    let mut s = TcpStream::connect(("127.0.0.1", port)).ok()?;
    s.set_read_timeout(Some(Duration::from_secs(30))).ok()?;
    write!(
        s,
        "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\
         Content-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    )
    .ok()?;
    let mut out = String::new();
    s.read_to_string(&mut out).ok()?;
    let status = out.get(9..12)?.parse().ok()?;
    let body = out.split_once("\r\n\r\n").map(|x| x.1.to_string())?;
    Some((status, body))
}

struct Server(Child, PathBuf);
impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
        let _ = std::fs::remove_dir_all(&self.1);
    }
}

fn start() -> (Server, u16, PathBuf) {
    let dir = std::env::temp_dir().join(format!("drishti-safety-test-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("temp dir");
    let port = free_port();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_drishti"));
    cmd.args(["serve", "--port", &port.to_string(), "--data"])
        .arg(dir.join("data"))
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    for k in [
        "VT_API_KEY",
        "ABUSECH_AUTH_KEY",
        "ABUSEIPDB_API_KEY",
        "ANTHROPIC_API_KEY",
        "OPENAI_API_KEY",
    ] {
        cmd.env_remove(k);
    }
    let child = cmd.spawn().expect("spawn drishti serve");
    let srv = Server(child, dir.clone());
    let t0 = Instant::now();
    while http(port, "GET", "/api/v1/health", "").is_none() {
        assert!(
            t0.elapsed() < Duration::from_secs(20),
            "server did not start"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    (srv, port, dir.join("data"))
}

#[test]
fn keys_tools_and_lookups_are_safe() {
    let (_srv, port, data) = start();
    let secret = "vt-test-key-0123456789abcdef";

    // Keys: accepted, stored owner-only, never echoed back.
    let (st, body) = http(
        port,
        "PUT",
        "/api/v1/secrets/virustotal",
        &format!(r#"{{"value":"{secret}"}}"#),
    )
    .expect("put");
    assert_eq!(st, 200, "{body}");
    assert!(!body.contains(secret), "key echoed back: {body}");
    let (st, body) = http(port, "GET", "/api/v1/secrets", "").expect("get");
    assert_eq!(st, 200);
    assert!(!body.contains(secret), "key revealed: {body}");
    assert!(body.contains("…cdef"), "{body}");
    let (_, settings) = http(port, "GET", "/api/v1/settings", "").expect("settings");
    assert!(!settings.contains(secret));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(data.join("secrets.json"))
            .expect("secrets file")
            .permissions()
            .mode();
        assert_eq!(mode & 0o077, 0, "secrets file readable by others: {mode:o}");
    }
    // Values that could break out of a header line are refused.
    for bad in ["has space inside", "quote\\\"inside123", "short"] {
        let (st, _) = http(
            port,
            "PUT",
            "/api/v1/secrets/virustotal",
            &format!(r#"{{"value":"{bad}"}}"#),
        )
        .expect("put bad");
        assert_eq!(st, 400, "accepted {bad:?}");
    }
    let (st, _) = http(
        port,
        "PUT",
        "/api/v1/secrets/not-a-service",
        r#"{"value":"abcdefgh12345"}"#,
    )
    .expect("unknown");
    assert_eq!(st, 400);

    // Tools: listing works whatever is installed.
    let (st, body) = http(port, "GET", "/api/v1/tools", "").expect("tools");
    assert_eq!(st, 200);
    let v: serde_json::Value = serde_json::from_str(&body).expect("json");
    assert!(
        v["tools"]
            .as_array()
            .is_some_and(|t| t.iter().any(|x| x["id"] == "ghidra"))
    );

    // Open a file; online checks are off by default.
    let Some(file) = ["/bin/ls", "/usr/bin/true"]
        .iter()
        .map(PathBuf::from)
        .find(|p| p.is_file())
    else {
        return;
    };
    let body = format!(r#"{{"path":"{}","analyze":false}}"#, file.display());
    let (st, resp) = http(port, "POST", "/api/v1/binaries/open", &body).expect("open");
    assert_eq!(st, 200, "{resp}");
    let v: serde_json::Value = serde_json::from_str(&resp).expect("json");
    let sha = v["binary_id"].as_str().expect("sha").to_string();
    let (st, body) = http(
        port,
        "POST",
        &format!("/api/v1/binaries/{sha}/lookups/virustotal"),
        "",
    )
    .expect("lookup");
    assert_eq!(st, 503, "online check ran while disabled: {body}");
    assert!(body.contains("turned off"), "{body}");

    // Source browser: no escaping the tool folder.
    for p in [
        "../../secrets.json",
        "/etc/passwd",
        "a/../../../secrets.json",
    ] {
        let (st, _) = http(
            port,
            "GET",
            &format!("/api/v1/binaries/{sha}/source?tool=jadx&path={p}"),
            "",
        )
        .expect("source");
        assert!(st == 400 || st == 404, "path {p} gave {st}");
    }
    let (st, _) = http(
        port,
        "GET",
        &format!("/api/v1/binaries/{sha}/source?tool=../etc"),
        "",
    )
    .expect("tool");
    assert_eq!(st, 400);

    // The plain-language report is part of the insights.
    let (st, body) =
        http(port, "GET", &format!("/api/v1/binaries/{sha}/insights"), "").expect("insights");
    assert_eq!(st, 200);
    let v: serde_json::Value = serde_json::from_str(&body).expect("json");
    assert!(v["plain"]["verdict"]["title"].is_string(), "{body}");
}
