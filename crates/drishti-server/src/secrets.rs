//! API keys for opt-in cloud services (spec §8.6): kept on the server only,
//! in `<data>/secrets.json` with owner-only permissions (0600), or taken
//! from environment variables, which win. The API reports whether a key is
//! set (and its last 4 characters), never the key itself, and nothing here
//! is logged.

use crate::state::Shared;
use serde_json::{Map, Value, json};
use std::path::PathBuf;

pub struct KeyDef {
    pub id: &'static str,
    pub env: &'static str,
    pub label: &'static str,
    pub get_url: &'static str,
}

pub const KEYS: &[KeyDef] = &[
    KeyDef {
        id: "anthropic",
        env: "ANTHROPIC_API_KEY",
        label: "Anthropic (Claude)",
        get_url: "https://console.anthropic.com/settings/keys",
    },
    KeyDef {
        id: "openai",
        env: "OPENAI_API_KEY",
        label: "OpenAI",
        get_url: "https://platform.openai.com/api-keys",
    },
    KeyDef {
        id: "gemini",
        env: "GEMINI_API_KEY",
        label: "Google Gemini",
        get_url: "https://aistudio.google.com/app/apikey",
    },
    KeyDef {
        id: "openrouter",
        env: "OPENROUTER_API_KEY",
        label: "OpenRouter",
        get_url: "https://openrouter.ai/keys",
    },
    KeyDef {
        id: "groq",
        env: "GROQ_API_KEY",
        label: "Groq",
        get_url: "https://console.groq.com/keys",
    },
    KeyDef {
        id: "virustotal",
        env: "VT_API_KEY",
        label: "VirusTotal",
        get_url: "https://www.virustotal.com/gui/my-apikey",
    },
    KeyDef {
        id: "abusech",
        env: "ABUSECH_AUTH_KEY",
        label: "abuse.ch (MalwareBazaar, URLhaus)",
        get_url: "https://auth.abuse.ch/",
    },
    KeyDef {
        id: "abuseipdb",
        env: "ABUSEIPDB_API_KEY",
        label: "AbuseIPDB",
        get_url: "https://www.abuseipdb.com/account/api",
    },
];

fn path(st: &Shared) -> PathBuf {
    st.data_dir.join("secrets.json")
}

fn read_file(st: &Shared) -> Map<String, Value> {
    std::fs::read(path(st))
        .ok()
        .and_then(|b| serde_json::from_slice::<Value>(&b).ok())
        .and_then(|v| v.as_object().cloned())
        .unwrap_or_default()
}

fn def(id: &str) -> Option<&'static KeyDef> {
    KEYS.iter().find(|k| k.id == id)
}

/// The key for `id`: environment variable first, then the secrets file.
pub fn get(st: &Shared, id: &str) -> Option<String> {
    let d = def(id)?;
    if let Ok(v) = std::env::var(d.env)
        && !v.trim().is_empty()
    {
        return Some(v.trim().to_string());
    }
    read_file(st)
        .get(id)
        .and_then(|v| v.as_str())
        .map(str::to_string)
        .filter(|s| !s.is_empty())
}

/// Which keys are set, without revealing them.
pub fn status(st: &Shared) -> Value {
    let file = read_file(st);
    let mut out = Vec::new();
    for d in KEYS {
        let env = std::env::var(d.env).ok().filter(|v| !v.trim().is_empty());
        let stored = file
            .get(d.id)
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty());
        let val = env.as_deref().or(stored);
        let hint = val.map(|v| {
            let tail: String = v
                .chars()
                .rev()
                .take(4)
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .collect();
            format!("…{tail}")
        });
        out.push(json!({
            "id": d.id, "label": d.label, "env": d.env, "get_url": d.get_url,
            "set": val.is_some(),
            "source": if env.is_some() { "environment" } else if stored.is_some() { "saved" } else { "none" },
            "hint": hint,
        }));
    }
    json!({ "keys": out })
}

/// Reject anything that isn't a plausible API key (also keeps the value
/// safe to place in a curl config line).
pub fn valid_key(v: &str) -> bool {
    (8..=512).contains(&v.len())
        && v.bytes()
            .all(|b| b.is_ascii_graphic() && b != b'"' && b != b'\\' && b != b'\'')
}

/// Save (`Some`) or remove (`None`) a key in the secrets file.
pub fn set(st: &Shared, id: &str, value: Option<&str>) -> Result<(), String> {
    def(id).ok_or("unknown key")?;
    let mut m = read_file(st);
    match value.map(str::trim) {
        Some(v) if !v.is_empty() => {
            if !valid_key(v) {
                return Err(
                    "that doesn't look like an API key (no spaces or quotes, 8–512 characters)"
                        .into(),
                );
            }
            m.insert(id.to_string(), Value::String(v.to_string()));
        }
        _ => {
            m.remove(id);
        }
    }
    write_private(
        &path(st),
        &serde_json::to_vec_pretty(&Value::Object(m)).map_err(|e| e.to_string())?,
    )
}

/// Write a file readable only by the owner (atomic rename).
fn write_private(p: &std::path::Path, data: &[u8]) -> Result<(), String> {
    use std::io::Write;
    let tmp = p.with_extension(format!("tmp{}", std::process::id()));
    {
        let mut o = std::fs::OpenOptions::new();
        o.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            o.mode(0o600);
        }
        let mut f = o.open(&tmp).map_err(|e| e.to_string())?;
        f.write_all(data).map_err(|e| e.to_string())?;
        f.sync_all().map_err(|e| e.to_string())?;
    }
    std::fs::rename(&tmp, p).map_err(|e| e.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn key_validation() {
        assert!(super::valid_key("sk-ant-api03-abcdEFGH_1234"));
        assert!(!super::valid_key("short"));
        assert!(!super::valid_key("has space in it"));
        assert!(!super::valid_key("quote\"inside1234"));
        assert!(!super::valid_key("newline\nurl=https://evil"));
    }
}
