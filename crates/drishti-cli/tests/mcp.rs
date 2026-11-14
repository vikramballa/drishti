//! MCP stdio round trip: spawn `drishti mcp`, speak JSON-RPC 2.0 over
//! stdin/stdout, and check initialise, tool listing, tool calls, renames
//! persisted to the data directory, and error handling.

use serde_json::{Value, json};
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

struct Mcp {
    child: Child,
    stdin: Option<ChildStdin>,
    stdout: BufReader<ChildStdout>,
}

impl Mcp {
    fn start(data: &std::path::Path) -> Mcp {
        let mut child = Command::new(env!("CARGO_BIN_EXE_drishti"))
            .arg("mcp")
            .arg("--data")
            .arg(data)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("spawn drishti mcp");
        let stdin = child.stdin.take();
        let stdout = BufReader::new(child.stdout.take().expect("stdout"));
        Mcp {
            child,
            stdin,
            stdout,
        }
    }

    fn send_raw(&mut self, line: &str) {
        let w = self.stdin.as_mut().expect("stdin open");
        writeln!(w, "{line}").expect("write");
        w.flush().expect("flush");
    }

    fn recv(&mut self) -> Value {
        let mut line = String::new();
        self.stdout.read_line(&mut line).expect("read");
        assert!(!line.is_empty(), "server closed stdout");
        serde_json::from_str(&line).unwrap_or_else(|e| panic!("bad JSON {line:?}: {e}"))
    }

    fn call(&mut self, id: u64, method: &str, params: Value) -> Value {
        self.send_raw(
            &json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}).to_string(),
        );
        let r = self.recv();
        assert_eq!(r["jsonrpc"], "2.0");
        assert_eq!(r["id"], id, "reply id mismatch: {r}");
        r
    }

    fn tool(&mut self, id: u64, name: &str, args: Value) -> (bool, String) {
        let r = self.call(id, "tools/call", json!({"name": name, "arguments": args}));
        let res = &r["result"];
        let text = res["content"][0]["text"].as_str().unwrap_or("").to_string();
        (res["isError"].as_bool().unwrap_or(true), text)
    }
}

impl Drop for Mcp {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn tmpdir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("drishti-mcp-{tag}-{}", std::process::id()));
    std::fs::create_dir_all(&d).expect("mkdir");
    d
}

/// A native binary to inspect: a corpus program when clang exists,
/// otherwise the `drishti` executable itself.
fn sample(dir: &std::path::Path) -> PathBuf {
    let src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../corpus/src/netclient.c");
    let out = dir.join("netclient");
    let ok = Command::new("clang")
        .arg("-O1")
        .arg("-o")
        .arg(&out)
        .arg(&src)
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if ok {
        out
    } else {
        PathBuf::from(env!("CARGO_BIN_EXE_drishti"))
    }
}

#[test]
fn mcp_stdio_round_trip() {
    let dir = tmpdir("rt");
    let data = dir.join("data");
    let bin = sample(&dir);
    let path = bin.to_string_lossy().to_string();
    let mut m = Mcp::start(&data);

    // Handshake.
    let r = m.call(
        1,
        "initialize",
        json!({"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "test", "version": "0"}}),
    );
    assert_eq!(r["result"]["serverInfo"]["name"], "drishti");
    assert_eq!(r["result"]["protocolVersion"], "2025-06-18");
    assert!(r["result"]["capabilities"]["tools"].is_object());
    // Notifications get no reply: the next reply must belong to id 2.
    m.send_raw(r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#);
    let r = m.call(2, "ping", json!({}));
    assert!(r["result"].is_object());

    // Tool listing: every tool has a schema.
    let r = m.call(3, "tools/list", json!({}));
    let tools = r["result"]["tools"].as_array().expect("tools");
    let names: Vec<&str> = tools.iter().filter_map(|t| t["name"].as_str()).collect();
    for want in [
        "open_binary",
        "list_functions",
        "function",
        "disassemble",
        "xrefs_to",
        "strings",
        "imports",
        "search_bytes",
        "rename",
        "comment",
    ] {
        assert!(names.contains(&want), "missing tool {want}: {names:?}");
    }
    assert!(tools.iter().all(|t| t["inputSchema"]["type"] == "object"));

    // open_binary returns JSON facts.
    let (err, text) = m.tool(4, "open_binary", json!({"path": path}));
    assert!(!err, "{text}");
    let facts: Value = serde_json::from_str(&text).expect("open_binary JSON");
    assert!(facts["functions"].as_u64().unwrap_or(0) > 0);
    assert_eq!(facts["sha256"].as_str().map(str::len), Some(64));
    assert!(facts["summary"].as_str().is_some_and(|s| !s.is_empty()));

    // list_functions → pick a real (non-thunk) function.
    let (err, text) = m.tool(
        5,
        "list_functions",
        json!({"path": path, "sort": "size", "limit": 5}),
    );
    assert!(!err, "{text}");
    let addr = text
        .lines()
        .skip(2)
        .find(|l| !l.contains("[import thunk]"))
        .and_then(|l| l.split_whitespace().next())
        .expect("a function line")
        .to_string();
    assert!(addr.starts_with("0x"), "{text}");

    // function / disassemble / xrefs work on that address.
    let (err, text) = m.tool(6, "function", json!({"path": path, "addr": addr}));
    assert!(!err && !text.is_empty(), "{text}");
    let (err, text) = m.tool(
        7,
        "disassemble",
        json!({"path": path, "addr": addr, "count": 4}),
    );
    assert!(!err && text.lines().count() >= 4, "{text}");
    let (err, _) = m.tool(8, "xrefs_to", json!({"path": path, "addr": addr}));
    assert!(!err);

    // Rename is persisted and visible in later listings.
    let (err, text) = m.tool(
        9,
        "rename",
        json!({"path": path, "addr": addr, "name": "renamed_by_test"}),
    );
    assert!(!err && text.contains("saved"), "{text}");
    let (err, text) = m.tool(
        10,
        "list_functions",
        json!({"path": path, "filter": "renamed_by_test"}),
    );
    assert!(
        !err && text.contains(&addr) && text.starts_with("1 functions"),
        "{text}"
    );
    assert!(data.join("drishti.db").is_file());

    // Errors are reported in-band, and the session survives them.
    let (err, text) = m.tool(
        11,
        "rename",
        json!({"path": path, "addr": "0x1", "name": "x"}),
    );
    assert!(err, "{text}");
    let (err, _) = m.tool(12, "function", json!({}));
    assert!(err);
    let (err, _) = m.tool(13, "open_binary", json!({"path": "/nonexistent/file"}));
    assert!(err);
    let (err, text) = m.tool(14, "no_such_tool", json!({"path": path}));
    assert!(err && text.contains("unknown tool"), "{text}");
    m.send_raw("this is not json");
    let r = m.recv();
    assert_eq!(r["error"]["code"], -32700);
    assert!(r["id"].is_null());
    let r = m.call(15, "no/such/method", json!({}));
    assert_eq!(r["error"]["code"], -32601);

    // Closing stdin ends the server cleanly.
    m.stdin.take();
    let status = m.child.wait().expect("wait");
    assert!(status.success(), "exit status {status}");

    // The analysis was persisted; a new session reuses it and sees the rename.
    let cached: Vec<_> = std::fs::read_dir(data.join("cache"))
        .expect("cache dir")
        .flatten()
        .filter(|e| e.path().extension().is_some_and(|x| x == "bin"))
        .collect();
    assert_eq!(cached.len(), 1, "one persisted analysis");
    let mut m = Mcp::start(&data);
    let (err, text) = m.tool(
        1,
        "list_functions",
        json!({"path": path, "filter": "renamed_by_test"}),
    );
    assert!(!err && text.contains(&addr), "{text}");
    drop(m);
    let _ = std::fs::remove_dir_all(&dir);
}
