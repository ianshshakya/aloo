//! Bounded-concurrency async worker pool.
//!
//! Uses `tokio::sync::Semaphore` to cap concurrent tasks at `max_workers`.

use std::future::Future;
use std::sync::Arc;

use tokio::sync::Semaphore;
use tracing::{debug, info};

use crate::scheduler::ScanTask;

/// Runs `ScanTask` items with a bounded concurrency limit.
pub struct WorkerPool {
    /// Maximum number of tasks executing concurrently.
    pub max_workers: usize,
}

impl WorkerPool {
    /// Create a pool with the given concurrency limit.
    pub fn new(max_workers: usize) -> Self {
        assert!(max_workers > 0, "max_workers must be > 0");
        Self { max_workers }
    }

    /// Execute all tasks with bounded concurrency.
    ///
    /// `f` is called for each task once a semaphore permit is available.
    /// All spawned futures are joined before this function returns.
    pub async fn execute<F, Fut>(&self, tasks: Vec<ScanTask>, f: F)
    where
        F: Fn(ScanTask) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        let sem = Arc::new(Semaphore::new(self.max_workers));
        let f   = Arc::new(f);
        let n   = tasks.len();
        debug!(tasks = n, max_workers = self.max_workers, "WorkerPool: starting tasks");

        let mut handles = Vec::with_capacity(n);
        for task in tasks {
            let sem = sem.clone();
            let f   = f.clone();
            let handle = tokio::spawn(async move {
                let _permit = sem.acquire_owned().await.expect("semaphore closed");
                f(task).await;
            });
            handles.push(handle);
        }

        for handle in handles {
            if let Err(e) = handle.await {
                tracing::warn!("Worker task panicked: {:?}", e);
            }
        }
        info!(tasks = n, "WorkerPool: all tasks complete");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aloo_core::{PortRange, SessionId};
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn make_tasks(n: usize) -> Vec<ScanTask> {
        let session = SessionId::new();
        (0..n)
            .map(|i| {
                let ip = format!("10.0.0.{}", i + 1).parse().unwrap();
                ScanTask::new(ip, PortRange::single(80), session)
            })
            .collect()
    }

    #[tokio::test]
    async fn executes_all_tasks() {
        let pool    = WorkerPool::new(4);
        let counter = Arc::new(AtomicUsize::new(0));
        let tasks   = make_tasks(10);

        let c = counter.clone();
        pool.execute(tasks, move |_task| {
            let c = c.clone();
            async move { c.fetch_add(1, Ordering::Relaxed); }
        })
        .await;

        assert_eq!(counter.load(Ordering::Relaxed), 10);
    }

    #[tokio::test]
    async fn respects_concurrency_limit() {
        let pool    = WorkerPool::new(2);
        let active  = Arc::new(AtomicUsize::new(0));
        let peak    = Arc::new(AtomicUsize::new(0));
        let tasks   = make_tasks(8);

        let a = active.clone();
        let p = peak.clone();
        pool.execute(tasks, move |_task| {
            let a = a.clone();
            let p = p.clone();
            async move {
                let cur = a.fetch_add(1, Ordering::SeqCst) + 1;
                p.fetch_max(cur, Ordering::SeqCst);
                tokio::time::sleep(tokio::time::Duration::from_millis(5)).await;
                a.fetch_sub(1, Ordering::SeqCst);
            }
        })
        .await;

        // Peak concurrency should never exceed max_workers (2)
        assert!(peak.load(Ordering::Relaxed) <= 2);
    }

    #[tokio::test]
    async fn empty_task_list_completes_immediately() {
        let pool = WorkerPool::new(4);
        pool.execute(vec![], |_: ScanTask| async {}).await;
    }
}
