//! HTTP server behaviour that unit tests can't see: spawn `drishti serve`,
//! open a file in place, then hit it with concurrent requests. A binary that
//! is not in memory yet must be loaded once, not once per request (each load
//! holds a full image + analysis; parallel UI requests used to multiply it).

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

fn sample() -> Option<PathBuf> {
    ["/bin/ls", "/usr/bin/true", "/bin/sh"]
        .iter()
        .map(PathBuf::from)
        .find(|p| p.is_file())
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .and_then(|l| l.local_addr())
        .map(|a| a.port())
        .expect("free port")
}

/// Minimal HTTP/1.1 client: returns (status, body).
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

struct Server {
    child: Child,
    log: PathBuf,
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[test]
fn concurrent_requests_load_a_binary_once() {
    let Some(file) = sample() else { return };
    let dir = std::env::temp_dir().join(format!("drishti-srv-test-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("temp dir");
    let port = free_port();
    let log = dir.join("server.log");
    let out = std::fs::File::create(&log).expect("log file");
    let child = Command::new(env!("CARGO_BIN_EXE_drishti"))
        .args(["serve", "--port", &port.to_string(), "--data"])
        .arg(dir.join("data"))
        .env("RUST_LOG", "info")
        .stdout(Stdio::from(out.try_clone().expect("dup")))
        .stderr(Stdio::from(out))
        .spawn()
        .expect("spawn drishti serve");
    let srv = Server { child, log };

    let t0 = Instant::now();
    while http(port, "GET", "/api/v1/health", "").is_none() {
        assert!(
            t0.elapsed() < Duration::from_secs(20),
            "server did not start"
        );
        std::thread::sleep(Duration::from_millis(50));
    }

    // Register in place without starting analysis: nothing is loaded yet.
    let body = format!(r#"{{"path":"{}","analyze":false}}"#, file.display());
    let (st, resp) = http(port, "POST", "/api/v1/binaries/open", &body).expect("open");
    assert_eq!(st, 200, "{resp}");
    let v: serde_json::Value = serde_json::from_str(&resp).expect("json");
    let sha = v["binary_id"].as_str().expect("binary_id").to_string();

    // Second open of the unchanged file reuses the stored hash.
    let (st, resp2) = http(port, "POST", "/api/v1/binaries/open", &body).expect("reopen");
    assert_eq!(st, 200);
    let v2: serde_json::Value = serde_json::from_str(&resp2).expect("json");
    assert_eq!(v2["binary_id"].as_str(), Some(sha.as_str()));

    let threads: Vec<_> = (0..8)
        .map(|_| {
            let path = format!("/api/v1/binaries/{sha}/strings?limit=5");
            std::thread::spawn(move || http(port, "GET", &path, "").map(|r| r.0))
        })
        .collect();
    for t in threads {
        assert_eq!(t.join().expect("thread"), Some(200));
    }

    let text = std::fs::read_to_string(&srv.log).expect("read log");
    let loads = text
        .lines()
        .filter(|l| l.contains(&format!("session {} loaded", &sha[..12])))
        .count();
    assert_eq!(loads, 1, "expected one session load, log:\n{text}");
    drop(srv);
    let _ = std::fs::remove_dir_all(&dir);
}
