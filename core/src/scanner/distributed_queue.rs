//! Multi-Node Distributed Task Queue & Cluster Orchestration
//!
//! Enables fleet-scale horizontal distribution of PQCanary cryptographic audits
//! across heterogeneous worker nodes with heartbeat monitoring, fault-tolerant job leasing,
//! distributed result storage, and Git repository fetching.

use serde::{Deserialize, Serialize};
use redis::AsyncCommands;
use std::time::{SystemTime, UNIX_EPOCH};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::sync::Mutex;
use crate::scanner::orchestrator::ComprehensiveFinding;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanJob {
    pub job_id: String,
    pub repository_url: String,
    pub tenant_id: String,
    pub commit_hash: String,
    pub submitted_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum WorkerStatus {
    Idle,
    Busy,
    Draining,
    Offline,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerNodeInfo {
    pub worker_id: String,
    pub hostname: String,
    pub status: WorkerStatus,
    pub last_heartbeat_epoch: u64,
    pub jobs_completed: u64,
    pub active_job_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobExecutionResult {
    pub job_id: String,
    pub worker_id: String,
    pub status: String,
    pub total_findings: usize,
    pub critical_count: usize,
    pub high_count: usize,
    pub findings: Vec<ComprehensiveFinding>,
    pub completed_at: u64,
}

pub struct DistributedClusterWorker {
    pub worker_id: String,
    pub hostname: String,
    redis_client: Option<redis::Client>,
    pending_queue_key: String,
    worker_registry_prefix: String,
    result_store_prefix: String,
    jobs_completed: AtomicU64,
    // Embedded in-memory coordinator fallback for local multi-node clusters
    in_memory_jobs: Arc<Mutex<std::collections::VecDeque<ScanJob>>>,
    in_memory_results: Arc<Mutex<std::collections::HashMap<String, JobExecutionResult>>>,
}

impl DistributedClusterWorker {
    pub fn new(worker_id: &str, redis_url_opt: Option<&str>) -> Result<Self, String> {
        let hostname = std::env::var("HOSTNAME")
            .or_else(|_| std::env::var("COMPUTERNAME"))
            .unwrap_or_else(|_| "node-worker".to_string());

        let client = if let Some(url) = redis_url_opt {
            Some(redis::Client::open(url).map_err(|e| format!("Redis connection error: {}", e))?)
        } else {
            None
        };

        Ok(Self {
            worker_id: worker_id.to_string(),
            hostname,
            redis_client: client,
            pending_queue_key: "pqcanary:cluster:jobs:pending".to_string(),
            worker_registry_prefix: "pqcanary:cluster:workers:".to_string(),
            result_store_prefix: "pqcanary:cluster:results:".to_string(),
            jobs_completed: AtomicU64::new(0),
            in_memory_jobs: Arc::new(Mutex::new(std::collections::VecDeque::new())),
            in_memory_results: Arc::new(Mutex::new(std::collections::HashMap::new())),
        })
    }

    fn now_epoch() -> u64 {
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
    }

    /// Register worker node in the cluster registry and send heartbeat with 60s TTL.
    pub async fn send_heartbeat(&self, status: WorkerStatus, active_job_id: Option<String>) -> Result<(), String> {
        let info = WorkerNodeInfo {
            worker_id: self.worker_id.clone(),
            hostname: self.hostname.clone(),
            status,
            last_heartbeat_epoch: Self::now_epoch(),
            jobs_completed: self.jobs_completed.load(Ordering::Relaxed),
            active_job_id,
        };

        if let Some(ref client) = self.redis_client {
            let mut con = client.get_multiplexed_async_connection().await
                .map_err(|e| format!("Failed to connect to Redis: {}", e))?;
            let key = format!("{}{}", self.worker_registry_prefix, self.worker_id);
            let json = serde_json::to_string(&info).map_err(|e| e.to_string())?;

            // Set with 60s expiration
            con.set_ex::<_, _, ()>(&key, json, 60).await
                .map_err(|e| format!("Redis heartbeat error: {}", e))?;
        }
        Ok(())
    }

    /// Submit a scan job into the distributed cluster queue.
    pub async fn submit_job(&self, job: ScanJob) -> Result<(), String> {
        if let Some(ref client) = self.redis_client {
            let mut con = client.get_multiplexed_async_connection().await
                .map_err(|e| format!("Redis connect failure: {}", e))?;
            let json_data = serde_json::to_string(&job).map_err(|e| e.to_string())?;
            con.rpush::<_, _, ()>(&self.pending_queue_key, json_data).await
                .map_err(|e| format!("Redis submit failure: {}", e))?;
        } else {
            let mut queue = self.in_memory_jobs.lock().await;
            queue.push_back(job);
        }
        Ok(())
    }

    /// Atomically lease a job from the distributed cluster queue (blocking pop).
    pub async fn claim_job(&self, timeout_sec: f64) -> Result<Option<ScanJob>, String> {
        if let Some(ref client) = self.redis_client {
            let safe_timeout = if timeout_sec.is_finite() && timeout_sec >= 0.0 { timeout_sec } else { 0.0 };
            let mut con = client.get_multiplexed_async_connection().await
                .map_err(|e| format!("Redis connect failure: {}", e))?;
            let result: Option<(String, String)> = con.blpop(&self.pending_queue_key, safe_timeout).await
                .map_err(|e| format!("Redis blpop error: {}", e))?;

            if let Some((_, json_data)) = result {
                let job = serde_json::from_str(&json_data)
                    .map_err(|e| format!("Job deserialization error: {}", e))?;
                return Ok(Some(job));
            }
            Ok(None)
        } else {
            let mut queue = self.in_memory_jobs.lock().await;
            Ok(queue.pop_front())
        }
    }

    /// Execute a claimed job: handles remote Git repository fetch, runs MasterOrchestrator,
    /// stores the full finding results in the cluster results store, and updates node status.
    pub async fn execute_job(&self, job: &ScanJob) -> Result<JobExecutionResult, String> {
        self.send_heartbeat(WorkerStatus::Busy, Some(job.job_id.clone())).await.ok();

        let target = job.repository_url.trim();
        let findings = if crate::scanner::git_cloner::GitRepositoryFetcher::is_git_repository_url(target) {
            let fetcher = crate::scanner::git_cloner::GitRepositoryFetcher::new();
            let temp_dir = fetcher.fetch_repository(target).await?;
            let temp_str = temp_dir.to_string_lossy().to_string();
            let orchestrator = crate::scanner::orchestrator::MasterOrchestrator::new(&temp_str);
            let results = orchestrator.execute_full_scan();
            crate::scanner::git_cloner::GitRepositoryFetcher::cleanup_temp_dir(&temp_dir);
            results
        } else {
            let safe_target = crate::api::validate_local_path(target)
                .map_err(|e| format!("Worker rejected job path: {}", e.description))?;
            let orchestrator = crate::scanner::orchestrator::MasterOrchestrator::new(&safe_target);
            orchestrator.execute_full_scan()
        };

        let critical_count = findings.iter().filter(|f| f.severity == "CRITICAL").count();
        let high_count = findings.iter().filter(|f| f.severity == "HIGH").count();

        let result = JobExecutionResult {
            job_id: job.job_id.clone(),
            worker_id: self.worker_id.clone(),
            status: "COMPLETED".to_string(),
            total_findings: findings.len(),
            critical_count,
            high_count,
            findings,
            completed_at: Self::now_epoch(),
        };

        // Persist result in Redis or local store
        if let Some(ref client) = self.redis_client {
            if let Ok(mut con) = client.get_multiplexed_async_connection().await {
                let res_key = format!("{}{}", self.result_store_prefix, job.job_id);
                if let Ok(json) = serde_json::to_string(&result) {
                    // Retain results in Redis for 7 days (604,800s)
                    let _: Result<(), _> = con.set_ex(&res_key, json, 604_800).await;
                }
            }
        } else {
            let mut store = self.in_memory_results.lock().await;
            store.insert(job.job_id.clone(), result.clone());
        }

        self.jobs_completed.fetch_add(1, Ordering::Relaxed);
        self.send_heartbeat(WorkerStatus::Idle, None).await.ok();

        Ok(result)
    }

    /// Retrieve completed scan results for a job from the cluster store.
    pub async fn fetch_result(&self, job_id: &str) -> Result<Option<JobExecutionResult>, String> {
        if let Some(ref client) = self.redis_client {
            let mut con = client.get_multiplexed_async_connection().await
                .map_err(|e| format!("Redis connection error: {}", e))?;
            let res_key = format!("{}{}", self.result_store_prefix, job_id);
            let json_opt: Option<String> = con.get(&res_key).await
                .map_err(|e| format!("Redis get error: {}", e))?;

            if let Some(json) = json_opt {
                let res = serde_json::from_str(&json)
                    .map_err(|e| format!("Result parsing error: {}", e))?;
                return Ok(Some(res));
            }
            Ok(None)
        } else {
            let store = self.in_memory_results.lock().await;
            Ok(store.get(job_id).cloned())
        }
    }
}
