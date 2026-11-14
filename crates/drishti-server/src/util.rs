//! Small helpers shared by the server and CLI.

use sha2::{Digest, Sha256};
use std::sync::atomic::{AtomicU64, Ordering};

/// Format Unix seconds as RFC 3339 UTC (no chrono dependency).
pub fn rfc3339(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    // Howard Hinnant's civil_from_days.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        (rem / 60) % 60,
        rem % 60
    )
}

pub fn now() -> String {
    let d = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    rfc3339(d.as_secs())
}

/// 16-hex-char hash, used for option hashes and ids.
pub fn short_hash(data: &[u8]) -> String {
    drishti_loader::util::hex(&Sha256::digest(data)[..8])
}

/// Unique, sortable id: time-based prefix + counter.
pub fn new_id() -> String {
    static C: AtomicU64 = AtomicU64::new(0);
    let n = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let c = C.fetch_add(1, Ordering::Relaxed);
    format!(
        "{:x}{}",
        n,
        &short_hash(format!("{n}-{c}-{}", std::process::id()).as_bytes())[..6]
    )
}

#[cfg(test)]
mod tests {
    #[test]
    fn rfc() {
        assert_eq!(super::rfc3339(0), "1970-01-01T00:00:00Z");
        assert_eq!(super::rfc3339(1_762_819_200), "2025-11-11T00:00:00Z");
        assert_ne!(super::new_id(), super::new_id());
    }
}
