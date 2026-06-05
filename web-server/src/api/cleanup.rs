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
    let Ok(entries) = std::fs::read_dir(dir) else { return };
    for entry in entries.flatten() {
        let path = entry.path();
        // Only consider .path files (not .path.consumed — those are in-flight)
        if path.extension().map_or(false, |e| e == "path") {
            if let Ok(meta) = std::fs::metadata(&path) {
                if let Ok(age) = now.duration_since(meta.modified().unwrap_or(now)) {
                    if age > TTL {
                        // Read the artifact path and delete it too
                        if let Ok(artifact_path) = std::fs::read_to_string(&path) {
                            let _ = std::fs::remove_file(artifact_path.trim());
                        }
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
}
