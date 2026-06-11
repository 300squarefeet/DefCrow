use std::time::{Duration, SystemTime};
use tokio::time;

const TTL: Duration = Duration::from_secs(2 * 3600);
const INTERVAL: Duration = Duration::from_secs(5 * 60);

pub fn spawn_cleanup_task(artifacts_dir: String) {
    tokio::spawn(async move {
        let mut ticker = time::interval(INTERVAL);
        loop {
            ticker.tick().await;
            sweep(&artifacts_dir);
        }
    });
}

fn sweep(dir: &str) {
    let now = SystemTime::now();
    let canon_dir = match std::path::Path::new(dir).canonicalize() {
        Ok(p) => p,
        Err(_) => return,
    };
    let Ok(entries) = std::fs::read_dir(dir) else { return };
    for entry in entries.flatten() {
        let path = entry.path();
        // Only consider .path files whose stem is a safe identifier (no path traversal).
        // .path.consumed files are in-flight downloads; skip them.
        let stem_ok = path.file_stem()
            .and_then(|s| s.to_str())
            .map_or(false, |s| !s.is_empty() && s.len() <= 64
                && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));
        if path.extension().map_or(false, |e| e == "path") && stem_ok {
            if let Ok(meta) = std::fs::metadata(&path) {
                if let Ok(age) = now.duration_since(meta.modified().unwrap_or(now)) {
                    if age > TTL {
                        if let Ok(artifact_str) = std::fs::read_to_string(&path) {
                            let candidate = std::path::PathBuf::from(artifact_str.trim());
                            if let Ok(canon) = candidate.canonicalize() {
                                if canon.starts_with(&canon_dir) {
                                    let _ = std::fs::remove_file(&canon);
                                }
                            }
                        }
                        let _ = std::fs::remove_file(&path);
                    }
                }
            }
        }
    }
    sweep_smuggler(dir);
}

fn sweep_smuggler(artifacts_dir: &str) {
    let smuggler_dir = std::path::Path::new(artifacts_dir).join("smuggler");
    let now = SystemTime::now();
    let Ok(entries) = std::fs::read_dir(&smuggler_dir) else { return };
    for entry in entries.flatten() {
        let path = entry.path();
        // Only process .html files whose stem is a 32-char lowercase hex string (link_id format)
        let stem_ok = path.file_stem()
            .and_then(|s| s.to_str())
            .map_or(false, |s| s.len() == 32
                && s.chars().all(|c| matches!(c, '0'..='9' | 'a'..='f')));
        if path.extension().map_or(false, |e| e == "html") && stem_ok {
            if let Ok(meta) = std::fs::metadata(&path) {
                if let Ok(age) = now.duration_since(meta.modified().unwrap_or(now)) {
                    if age > TTL {
                        let _ = std::fs::remove_file(&path);
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sweep_deletes_expired_path_files() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();

        let path_file = dir.join("expired.path");
        let art_file = dir.join("artifact.bin");
        std::fs::write(&art_file, b"PAYLOAD").unwrap();
        std::fs::write(&path_file, art_file.to_str().unwrap()).unwrap();

        // File is fresh — sweep should not delete it
        sweep(dir.to_str().unwrap());
        assert!(path_file.exists(), "fresh .path file should not be deleted");
        assert!(art_file.exists(), "fresh artifact should not be deleted");
    }

    #[test]
    fn sweep_smuggler_preserves_fresh_html() {
        let tmp      = tempfile::tempdir().unwrap();
        let dir      = tmp.path();
        let smug_dir = dir.join("smuggler");
        std::fs::create_dir_all(&smug_dir).unwrap();

        let html_file = smug_dir.join("a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4.html");
        std::fs::write(&html_file, b"<html/>").unwrap();

        sweep_smuggler(dir.to_str().unwrap());
        assert!(html_file.exists(), "fresh smuggler html should not be deleted");
    }
}
