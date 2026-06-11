use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::watch;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "status", rename_all = "lowercase")]
pub enum JobStatus {
    Queued,
    Building { progress: u8, msg: String },
    Done     { download_id: String, #[serde(skip_serializing_if = "Option::is_none")] config_xml: Option<String> },
    Error    { msg: String },
}

struct JobEntry {
    status: JobStatus,
    tx:     watch::Sender<JobStatus>,
}

#[derive(Clone)]
pub struct JobStore {
    inner: Arc<DashMap<String, JobEntry>>,
}

impl JobStore {
    pub fn new() -> Self {
        Self { inner: Arc::new(DashMap::new()) }
    }

    pub fn create_job(&self) -> String {
        let id = Uuid::new_v4().to_string();
        let (tx, _rx) = watch::channel(JobStatus::Queued);
        self.inner.insert(id.clone(), JobEntry { status: JobStatus::Queued, tx });
        id
    }

    pub fn get_status(&self, id: &str) -> Option<JobStatus> {
        self.inner.get(id).map(|e| e.status.clone())
    }

    pub fn set_status(&self, id: &str, status: JobStatus) {
        if let Some(mut entry) = self.inner.get_mut(id) {
            let _ = entry.tx.send(status.clone());
            entry.status = status;
        }
    }

    pub fn subscribe(&self, id: &str) -> Option<watch::Receiver<JobStatus>> {
        self.inner.get(id).map(|e| e.tx.subscribe())
    }

    pub fn get_sender(&self, id: &str) -> Option<watch::Sender<JobStatus>> {
        self.inner.get(id).map(|e| e.tx.clone())
    }

    pub fn remove(&self, id: &str) {
        self.inner.remove(id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_job_lifecycle() {
        let store = JobStore::new();
        let id = store.create_job();
        assert!(matches!(store.get_status(&id), Some(JobStatus::Queued)));

        store.set_status(&id, JobStatus::Building { progress: 50, msg: "compiling".into() });
        match store.get_status(&id).unwrap() {
            JobStatus::Building { progress, .. } => assert_eq!(progress, 50),
            _ => panic!("expected Building"),
        }

        store.set_status(&id, JobStatus::Done { download_id: "xyz".into(), config_xml: None });
        assert!(matches!(store.get_status(&id), Some(JobStatus::Done { .. })));
    }

    #[test]
    fn test_unknown_job_returns_none() {
        let store = JobStore::new();
        assert!(store.get_status("nonexistent").is_none());
    }

    #[test]
    fn test_subscribe_returns_receiver() {
        let store = JobStore::new();
        let id = store.create_job();
        assert!(store.subscribe(&id).is_some());
        assert!(store.subscribe("bad-id").is_none());
    }
}
