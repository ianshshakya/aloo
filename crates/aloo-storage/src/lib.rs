//! `aloo-storage` — SQLite-backed scan history persistence.
//!
//! Uses `sqlx` with the Tokio runtime and the `sqlite` feature.
//! Migrations are schema-less for now; real DDL will be added in the
//! storage milestone.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::path::Path;

use aloo_core::{Host, PortId, ScanSession, Vulnerability};
use aloo_traits::StorageError;
use sqlx::SqlitePool;
use tracing::debug;

// ── Database handle ───────────────────────────────────────────────────────────

/// Owns the SQLite connection pool.
#[derive(Clone, Debug)]
pub struct Database {
    pool: SqlitePool,
}

impl Database {
    /// Open (or create) a database at the given path.
    pub async fn open(path: &Path) -> Result<Self, StorageError> {
        let url = format!("sqlite://{}", path.display());
        let pool = SqlitePool::connect(&url)
            .await
            .map_err(|e| StorageError::Database(e.to_string()))?;
        Ok(Self { pool })
    }

    /// Open an in-memory database (useful for testing).
    pub async fn new_in_memory() -> Result<Self, StorageError> {
        let pool = SqlitePool::connect(":memory:")
            .await
            .map_err(|e| StorageError::Database(e.to_string()))?;
        Ok(Self { pool })
    }

    /// Run pending schema migrations (no-op stub — DDL pending).
    pub async fn run_migrations(&self) -> Result<(), StorageError> {
        debug!("run_migrations stub — no DDL yet");
        Ok(())
    }

    /// Expose the inner pool (e.g. for repository construction).
    pub fn pool(&self) -> &SqlitePool {
        &self.pool
    }
}

// ── Scan Session Repository ───────────────────────────────────────────────────

/// CRUD operations for `ScanSession` records.
pub struct ScanRepository {
    pool: SqlitePool,
}

impl ScanRepository {
    /// Create from a `Database`.
    pub fn new(db: &Database) -> Self {
        Self { pool: db.pool.clone() }
    }

    /// Persist a scan session (stub — returns `Ok(())` until DDL exists).
    pub async fn save(&self, session: &ScanSession) -> Result<(), StorageError> {
        debug!(session_id = %session.id, "ScanRepository::save stub");
        Ok(())
    }

    /// Load a session by ID string (stub — returns `NotFound`).
    pub async fn find_by_id(&self, id: &str) -> Result<ScanSession, StorageError> {
        Err(StorageError::NotFound(format!("session {id}")))
    }

    /// List all sessions (stub — returns empty).
    pub async fn list_all(&self) -> Result<Vec<ScanSession>, StorageError> {
        Ok(vec![])
    }
}

// ── Host Repository ───────────────────────────────────────────────────────────

/// CRUD operations for `Host` records.
pub struct HostRepository {
    pool: SqlitePool,
}

impl HostRepository {
    /// Create from a `Database`.
    pub fn new(db: &Database) -> Self {
        Self { pool: db.pool.clone() }
    }

    /// Persist a host record (stub).
    pub async fn save(&self, host: &Host) -> Result<(), StorageError> {
        debug!(host_id = %host.id, ip = %host.ip, "HostRepository::save stub");
        Ok(())
    }

    /// List all hosts for a given session ID string (stub — returns empty).
    pub async fn list_by_session(&self, session_id: &str) -> Result<Vec<Host>, StorageError> {
        debug!(session_id, "HostRepository::list_by_session stub");
        Ok(vec![])
    }
}

// ── Vulnerability Repository ──────────────────────────────────────────────────

/// CRUD operations for `Vulnerability` records.
pub struct VulnRepository {
    pool: SqlitePool,
}

impl VulnRepository {
    /// Create from a `Database`.
    pub fn new(db: &Database) -> Self {
        Self { pool: db.pool.clone() }
    }

    /// Persist a vulnerability linked to a port (stub).
    pub async fn save(&self, vuln: &Vulnerability, port_id: PortId) -> Result<(), StorageError> {
        debug!(cve = %vuln.cve_id, port_id = %port_id, "VulnRepository::save stub");
        Ok(())
    }

    /// List all vulns for a port ID (stub — returns empty).
    pub async fn list_by_port(&self, port_id: PortId) -> Result<Vec<Vulnerability>, StorageError> {
        debug!(port_id = %port_id, "VulnRepository::list_by_port stub");
        Ok(vec![])
    }
}

// ── Storage façade ────────────────────────────────────────────────────────────

/// Bundles all repositories for convenient access.
pub struct Storage {
    /// Scan session repository.
    pub scans: ScanRepository,
    /// Host repository.
    pub hosts: HostRepository,
    /// Vulnerability repository.
    pub vulns: VulnRepository,
}

impl Storage {
    /// Construct from an opened `Database`.
    pub fn new(db: &Database) -> Self {
        Self {
            scans: ScanRepository::new(db),
            hosts: HostRepository::new(db),
            vulns: VulnRepository::new(db),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aloo_core::ScanSession;

    #[tokio::test]
    async fn in_memory_db_connects() {
        let db = Database::new_in_memory().await.expect("in-memory DB should connect");
        db.run_migrations().await.expect("migrations stub should succeed");
    }

    #[tokio::test]
    async fn scan_repository_save_stub() {
        let db = Database::new_in_memory().await.unwrap();
        let repo = ScanRepository::new(&db);
        let session = ScanSession::new(vec!["10.0.0.0/24".into()]);
        repo.save(&session).await.expect("stub save should succeed");
    }

    #[tokio::test]
    async fn scan_repository_find_returns_not_found() {
        let db = Database::new_in_memory().await.unwrap();
        let repo = ScanRepository::new(&db);
        let err = repo.find_by_id("non-existent").await.unwrap_err();
        assert!(matches!(err, StorageError::NotFound(_)));
    }

    #[tokio::test]
    async fn storage_facade_constructs() {
        let db = Database::new_in_memory().await.unwrap();
        let _storage = Storage::new(&db);
    }
}
