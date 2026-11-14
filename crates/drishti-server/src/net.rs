//! Outbound HTTPS for opt-in cloud features (cloud AI providers, hash and
//! address lookups) through the system `curl`, so the single binary needs
//! no TLS stack of its own (DECISIONS #32).
//!
//! Safety:
//! - Only `https://` URLs, no redirects, bounded time and size.
//! - Everything curl needs (URL, headers with API keys, body) goes through a
//!   config file on **stdin**, never the command line, so keys don't show up
//!   in `ps` output or shell history.
//! - Callers pass fixed provider URLs; user-configurable endpoints are
//!   limited to local mode (see `ai.rs`).

use std::process::Stdio;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::process::Command;
use tokio::sync::mpsc;

pub struct HttpReq<'a> {
    pub method: &'a str,
    pub url: String,
    /// Header lines `Name: value` (may carry secrets).
    pub headers: Vec<String>,
    pub body: Option<String>,
    pub timeout: Duration,
}

impl<'a> HttpReq<'a> {
    pub fn get(url: impl Into<String>) -> Self {
        HttpReq {
            method: "GET",
            url: url.into(),
            headers: Vec::new(),
            body: None,
            timeout: Duration::from_secs(30),
        }
    }
    pub fn post(url: impl Into<String>, content_type: &str, body: String) -> Self {
        HttpReq {
            method: "POST",
            url: url.into(),
            headers: vec![format!("Content-Type: {content_type}")],
            body: Some(body),
            timeout: Duration::from_secs(60),
        }
    }
    pub fn header(mut self, h: impl Into<String>) -> Self {
        self.headers.push(h.into());
        self
    }
}

fn curl_path() -> Option<std::path::PathBuf> {
    for p in [
        "/usr/bin/curl",
        "/opt/homebrew/bin/curl",
        "/usr/local/bin/curl",
    ] {
        let p = std::path::Path::new(p);
        if p.is_file() {
            return Some(p.to_path_buf());
        }
    }
    crate::tools::which("curl")
}

pub fn available() -> bool {
    curl_path().is_some()
}

/// Quote a value for a curl config file (`"…"` with `\\ \" \n \r \t`).
fn q(s: &str) -> String {
    let mut o = String::with_capacity(s.len() + 2);
    o.push('"');
    for c in s.chars() {
        match c {
            '\\' => o.push_str("\\\\"),
            '"' => o.push_str("\\\""),
            '\n' => o.push_str("\\n"),
            '\r' => o.push_str("\\r"),
            '\t' => o.push_str("\\t"),
            c if c.is_control() => {}
            c => o.push(c),
        }
    }
    o.push('"');
    o
}

fn config(req: &HttpReq<'_>) -> Result<String, String> {
    if !req.url.starts_with("https://") {
        return Err("only https:// addresses are allowed".into());
    }
    let mut c = String::new();
    c += &format!("url = {}\n", q(&req.url));
    c += &format!("request = {}\n", q(req.method));
    for h in &req.headers {
        if h.contains('\n') || h.contains('\r') {
            return Err("invalid header".into());
        }
        c += &format!("header = {}\n", q(h));
    }
    if let Some(b) = &req.body {
        c += &format!("data-binary = {}\n", q(b));
    }
    Ok(c)
}

fn base_cmd(req: &HttpReq<'_>) -> Result<Command, String> {
    let curl = curl_path().ok_or("curl is not installed, so online features are unavailable")?;
    let mut cmd = Command::new(curl);
    cmd.args([
        "--silent",
        "--show-error",
        "--proto",
        "=https",
        "--max-redirs",
        "0",
        "--connect-timeout",
        "10",
        "--max-time",
    ])
    .arg(req.timeout.as_secs().max(1).to_string())
    .args(["--user-agent", "drishti", "--config", "-"])
    .stdin(Stdio::piped())
    .stdout(Stdio::piped())
    .stderr(Stdio::piped())
    .kill_on_drop(true);
    Ok(cmd)
}

/// Make a request; returns (HTTP status, body ≤ `cap` bytes).
pub async fn fetch(req: HttpReq<'_>, cap: usize) -> Result<(u16, Vec<u8>), String> {
    let cfg = config(&req)?;
    let mut cmd = base_cmd(&req)?;
    cmd.args(["--write-out", "\n%{http_code}"]);
    let mut child = cmd.spawn().map_err(|e| format!("cannot start curl: {e}"))?;
    if let Some(mut si) = child.stdin.take() {
        si.write_all(cfg.as_bytes())
            .await
            .map_err(|e| e.to_string())?;
    }
    let mut out = Vec::new();
    if let Some(so) = child.stdout.take() {
        so.take(cap as u64 + 8)
            .read_to_end(&mut out)
            .await
            .map_err(|e| e.to_string())?;
    }
    let mut err = String::new();
    if let Some(se) = child.stderr.take() {
        let _ = se.take(4096).read_to_string(&mut err).await;
    }
    let status = child.wait().await.map_err(|e| e.to_string())?;
    let nl = out.iter().rposition(|&c| c == b'\n');
    let code = nl
        .and_then(|i| std::str::from_utf8(&out[i + 1..]).ok())
        .and_then(|s| s.trim().parse::<u16>().ok())
        .unwrap_or(0);
    if let Some(i) = nl {
        out.truncate(i);
    }
    if code == 0 {
        return Err(friendly_curl_error(status.code(), &err));
    }
    out.truncate(cap);
    Ok((code, out))
}

fn friendly_curl_error(code: Option<i32>, stderr: &str) -> String {
    match code {
        Some(6) => "no internet connection (could not find the server)".into(),
        Some(7) => "could not connect to the server".into(),
        Some(28) => "the server took too long to answer".into(),
        Some(35) | Some(60) => "secure connection failed".into(),
        _ => {
            let s = stderr.trim().trim_start_matches("curl: ");
            if s.is_empty() {
                "request failed".into()
            } else {
                s.chars().take(200).collect()
            }
        }
    }
}

/// Streaming response: the HTTP status, then body lines as they arrive.
pub struct Stream {
    pub status: u16,
    pub lines: mpsc::Receiver<Vec<u8>>,
}

/// Start a streaming request (server-sent events). Headers are read from
/// curl's stderr (`--dump-header`), so the status is known before the body.
pub async fn stream(req: HttpReq<'_>) -> Result<Stream, String> {
    let cfg = config(&req)?;
    let mut cmd = base_cmd(&req)?;
    cmd.args(["--no-buffer", "--dump-header", "/dev/stderr"]);
    let mut child = cmd.spawn().map_err(|e| format!("cannot start curl: {e}"))?;
    if let Some(mut si) = child.stdin.take() {
        si.write_all(cfg.as_bytes())
            .await
            .map_err(|e| e.to_string())?;
    }
    let stderr = child.stderr.take().ok_or("no stderr")?;
    let stdout = child.stdout.take().ok_or("no stdout")?;
    let mut er = BufReader::new(stderr);
    let mut status = 0u16;
    let mut errtxt = String::new();
    // Read header block(s); a "100 Continue" block may come first.
    loop {
        let mut line = String::new();
        let n = tokio::time::timeout(req.timeout, er.read_line(&mut line))
            .await
            .map_err(|_| "the server took too long to answer".to_string())?
            .map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        let l = line.trim();
        if let Some(rest) = l.strip_prefix("HTTP/") {
            status = rest
                .split_whitespace()
                .nth(1)
                .and_then(|c| c.parse().ok())
                .unwrap_or(0);
        } else if l.is_empty() && status >= 200 {
            break;
        } else if status == 0 {
            errtxt.push_str(l);
        }
    }
    if status == 0 {
        let st = child.wait().await.ok().and_then(|s| s.code());
        return Err(friendly_curl_error(st, &errtxt));
    }
    let (tx, rx) = mpsc::channel(64);
    tokio::spawn(async move {
        let mut rd = BufReader::new(stdout);
        loop {
            let mut buf = Vec::new();
            match rd.read_until(b'\n', &mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(_) => {
                    if buf.len() > 1 << 20 {
                        break;
                    }
                    if tx.send(buf).await.is_err() {
                        break; // receiver gone: drop child → curl killed
                    }
                }
            }
        }
        let _ = child.kill().await;
    });
    Ok(Stream { status, lines: rx })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_quoting_and_https_only() {
        let r = HttpReq::post(
            "https://api.example.com/v1",
            "application/json",
            "{\"a\":\"b\\n\"}\n".into(),
        )
        .header("x-api-key: k\"ey");
        let c = config(&r).unwrap();
        assert!(c.contains(r#"url = "https://api.example.com/v1""#));
        assert!(c.contains(r#"header = "x-api-key: k\"ey""#));
        assert!(c.contains(r#"data-binary = "{\"a\":\"b\\n\"}\n""#));
        assert!(config(&HttpReq::get("http://x")).is_err());
        assert!(config(&HttpReq::get("file:///etc/passwd")).is_err());
        let bad = HttpReq::get("https://x").header("a: b\nurl = \"https://evil\"");
        assert!(config(&bad).is_err());
    }
}
