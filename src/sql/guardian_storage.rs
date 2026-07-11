//! PostgreSQL-compatible SQL on top of GuardianDB's replicated document storage.
//!
//! This module (enabled by the `sql` feature) bridges the storage-agnostic
//! [`crate::relational::RelationalStorage`] boundary used by the
//! [`guardian_sql`] engine onto a GuardianDB [`DocumentStore`]. Each relational
//! table maps to a key-prefixed set of documents inside a single GuardianDB
//! document store; the catalog is one more document. Rows therefore replicate
//! exactly like any other GuardianDB document — preserving the local-first, P2P
//! model — while the relational engine reads a synchronous, locally-mirrored
//! view (the existing DocumentStore index).
//!
//! ```no_run
//! # async fn run(db: &guardian_db::guardian::GuardianDB) -> Result<(), Box<dyn std::error::Error>> {
//! use guardian_db::sql::open_sql;
//! use guardian_db::sql::engine::Session;
//!
//! let database = open_sql(db, "app").await?;
//! let mut session = Session::new(database, "guardian");
//! session.execute("CREATE TABLE users (id INT PRIMARY KEY, name TEXT)").await?;
//! session.execute("INSERT INTO users VALUES (1, 'Alice')").await?;
//! # Ok(()) }
//! ```

use crate::guardian::GuardianDB;
use crate::guardian::error::{GuardianError, Result as GuardianResult};
use crate::relational::error::Result as RelResult;
use crate::relational::{RelError, RelationalStorage};
use crate::sql::engine::{ChangeSource, Database, classify_change};
use crate::stores::document_store::EventDocsDiff;
use crate::traits::{Document, DocumentStore};
use async_trait::async_trait;
use serde_json::{Map, Value as Json};
use std::sync::Arc;
use tracing::warn;

/// Separator between a collection prefix and a row id in the GuardianDB key.
/// `0x1f` (unit separator) does not occur in the engine's row ids.
const SEP: char = '\u{1f}';
/// Reserved collection used to persist the serialized catalog.
const CATALOG_COLLECTION: &str = "__gdb_sql_catalog";

/// Consistency mode for the GuardianDB-backed SQL layer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum Consistency {
    /// Local-first: statements are atomic on the local replica; replication is
    /// asynchronous and converges by GuardianDB/CRDT (LWW) semantics. This is
    /// the default and matches GuardianDB's model.
    #[default]
    LocalFirst,
    /// Strict SQL: route writes through a single-writer leader so that
    /// uniqueness and ordering are globally enforced. The routing flag and API
    /// exist; the cross-node leader/coordinator is an in-progress component
    /// (see `docs/postgres-compat.md`).
    Strict,
}

/// A [`RelationalStorage`] implementation backed by a GuardianDB document store.
pub struct GuardianRelationalStorage {
    store: Arc<dyn DocumentStore<Error = GuardianError>>,
    consistency: Consistency,
}

impl GuardianRelationalStorage {
    pub fn new(store: Arc<dyn DocumentStore<Error = GuardianError>>) -> Self {
        Self {
            store,
            consistency: Consistency::LocalFirst,
        }
    }

    pub fn with_consistency(mut self, consistency: Consistency) -> Self {
        self.consistency = consistency;
        self
    }

    pub fn consistency(&self) -> Consistency {
        self.consistency
    }

    /// Re-synchronize the local document-store index from replicated state.
    ///
    /// The relational engine reads the DocumentStore's synchronous local index;
    /// that index updates on local writes and on `load`/`sync`, but not
    /// automatically when documents arrive from peers in the background. A
    /// gateway serving a replicating node should call this (e.g. periodically or
    /// before a read) to observe remote writes. Returns the number of rows
    /// re-synced.
    pub async fn refresh(&self) -> GuardianResult<()> {
        self.store.load(0).await
    }

    /// The underlying document-store handle. An escape hatch below the
    /// [`RelationalStorage`] abstraction for callers that need iroh-docs-level
    /// access — e.g. tests fabricating a peer-authored write to exercise the
    /// replicated-write realtime bridge (see `spawn_replication_bridge`),
    /// which real replication would otherwise require a second networked peer
    /// to produce.
    pub fn document_store(&self) -> &Arc<dyn DocumentStore<Error = GuardianError>> {
        &self.store
    }

    fn gkey(collection: &str, row_id: &str) -> String {
        format!("{collection}{SEP}{row_id}")
    }

    /// Persist a relational document wrapped with its GuardianDB key so that
    /// rows from different tables never collide on `_id`.
    async fn write_wrapped(&self, gkey: String, collection: &str, doc: &Json) -> RelResult<()> {
        let mut wrapped = Map::new();
        wrapped.insert("_id".to_string(), Json::String(gkey));
        wrapped.insert(
            "__collection".to_string(),
            Json::String(collection.to_string()),
        );
        wrapped.insert("doc".to_string(), doc.clone());
        let document: Document = Box::new(Json::Object(wrapped));
        self.store.put(document).await.map_err(map_err)?;
        Ok(())
    }

    fn unwrap_doc(bytes: &[u8]) -> RelResult<Option<Json>> {
        let wrapped: Json =
            serde_json::from_slice(bytes).map_err(|e| RelError::Storage(e.to_string()))?;
        Ok(wrapped.get("doc").cloned())
    }
}

fn map_err(e: GuardianError) -> RelError {
    RelError::Storage(e.to_string())
}

#[async_trait]
impl RelationalStorage for GuardianRelationalStorage {
    async fn scan(&self, collection: &str) -> RelResult<Vec<(String, Json)>> {
        let prefix = format!("{collection}{SEP}");
        let index = self.store.index();
        let keys = index.keys().map_err(map_err)?;
        let mut out = Vec::new();
        for key in keys {
            let Some(row_id) = key.strip_prefix(&prefix) else {
                continue;
            };
            if let Some(bytes) = index.get_bytes(&key).map_err(map_err)?
                && let Some(doc) = Self::unwrap_doc(&bytes)?
            {
                out.push((row_id.to_string(), doc));
            }
        }
        Ok(out)
    }

    async fn get(&self, collection: &str, row_id: &str) -> RelResult<Option<Json>> {
        let gkey = Self::gkey(collection, row_id);
        match self.store.index().get_bytes(&gkey).map_err(map_err)? {
            Some(bytes) => Self::unwrap_doc(&bytes),
            None => Ok(None),
        }
    }

    async fn put(&self, collection: &str, row_id: &str, doc: &Json) -> RelResult<()> {
        self.write_wrapped(Self::gkey(collection, row_id), collection, doc)
            .await
    }

    async fn delete(&self, collection: &str, row_id: &str) -> RelResult<()> {
        // Deleting a missing row is not an error.
        let _ = self.store.delete(&Self::gkey(collection, row_id)).await;
        Ok(())
    }

    async fn truncate(&self, collection: &str) -> RelResult<()> {
        let prefix = format!("{collection}{SEP}");
        let keys = self.store.index().keys().map_err(map_err)?;
        for key in keys {
            if key.starts_with(&prefix) {
                let _ = self.store.delete(&key).await;
            }
        }
        Ok(())
    }

    async fn load_catalog(&self) -> RelResult<Option<Json>> {
        self.get(CATALOG_COLLECTION, "catalog").await
    }

    async fn save_catalog(&self, catalog: &Json) -> RelResult<()> {
        self.put(CATALOG_COLLECTION, "catalog", catalog).await
    }
}

/// Open (or create) a relational SQL database backed by a GuardianDB document
/// store named `name`. The returned [`Database`] can be used to create
/// [`Session`](crate::sql::engine::Session)s or served over the wire with
/// `crate::pgwire::serve` (requires the `pgwire` feature).
pub async fn open_sql(
    db: &GuardianDB,
    name: &str,
) -> GuardianResult<Arc<Database<GuardianRelationalStorage>>> {
    open_sql_with(db, name, Consistency::LocalFirst).await
}

/// Like [`open_sql`] but selects a [`Consistency`] mode.
pub async fn open_sql_with(
    db: &GuardianDB,
    name: &str,
    consistency: Consistency,
) -> GuardianResult<Arc<Database<GuardianRelationalStorage>>> {
    let docs = db.docs(name, None).await?;
    let storage = Arc::new(GuardianRelationalStorage::new(docs).with_consistency(consistency));
    let database = Arc::new(Database::new(storage, name.to_string()));
    spawn_replication_bridge(&database).await;
    Ok(database)
}

/// Bridges peer-authored (replicated) document-store writes into the
/// engine's [`ChangeEvent`](crate::sql::engine::ChangeEvent) changefeed.
///
/// `Database::subscribe_changes` only observes commits made locally through a
/// [`Session`](crate::sql::engine::Session) on this node — replicated writes
/// land in the document store correctly but never reach that hook on their
/// own. `GuardianDBDocumentStore::refresh_doc_index` (driven by
/// `GuardianRelationalStorage::refresh` / the reactive live-sync task) diffs
/// foreign-authored index changes and broadcasts them as [`EventDocsDiff`]
/// batches on the store's [`EventBus`](crate::p2p::EventBus). This task
/// subscribes to that broadcast, reclassifies each diff through the same
/// [`classify_change`] logic local commits use (tagged
/// [`ChangeSource::Replicated`]), and delivers the result through
/// `database.emit_changes` — the exact channel local commits use, so realtime
/// subscribers (`crate::supabase::realtime`) see both without special-casing.
///
/// Best-effort: if the store's event bus can't be subscribed to, this simply
/// skips spawning (replicated changes then just aren't observed by realtime,
/// same as before this bridge existed) rather than failing `open_sql_with`.
/// Holds only a [`Weak`] reference to `database` so the bridge task can never
/// keep the database (and its storage/iroh handles) alive after every
/// external holder has dropped it.
async fn spawn_replication_bridge(database: &Arc<Database<GuardianRelationalStorage>>) {
    let store = database.storage().document_store();
    let event_bus = store.event_bus();
    let store_address = store.address().to_string();

    let mut rx = match event_bus.subscribe::<EventDocsDiff>().await {
        Ok(rx) => rx,
        Err(e) => {
            warn!(
                "Failed to subscribe to replicated-write events for store '{}'; realtime \
                 subscribers will not observe replicated writes on this store: {:?}",
                store_address, e
            );
            return;
        }
    };

    let weak_db = Arc::downgrade(database);

    tokio::spawn(async move {
        loop {
            let diff = match rx.recv().await {
                Ok(diff) => diff,
                Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                    warn!(
                        "Replicated-write bridge for store '{}' lagged by {} events; some \
                         replicated changes may not reach realtime subscribers",
                        store_address, n
                    );
                    continue;
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
            };

            // Check for external holders before doing any work: once the
            // last strong `Arc<Database<_>>` is gone, there's nothing left
            // to deliver to, so stop the task.
            let Some(database) = weak_db.upgrade() else {
                break;
            };

            if diff.address != store_address {
                continue;
            }

            let at = chrono::Utc::now();
            let mut events = Vec::new();
            for change in diff.changes {
                let old_doc = change
                    .old
                    .as_deref()
                    .and_then(|b| GuardianRelationalStorage::unwrap_doc(b).ok().flatten());
                let new_doc = change
                    .new
                    .as_deref()
                    .and_then(|b| GuardianRelationalStorage::unwrap_doc(b).ok().flatten());
                match classify_change(
                    old_doc.as_ref(),
                    new_doc.as_ref(),
                    at,
                    ChangeSource::Replicated,
                ) {
                    Some(ev) => events.push(ev),
                    None => tracing::trace!(
                        key = %change.key,
                        "replicated document diff for '{}' produced no observable row change (not a table row, or no liveness transition)",
                        store_address
                    ),
                }
            }
            database.emit_changes(events);
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::guardian::GuardianDB;
    use crate::guardian::core::NewGuardianDBOptions;
    use crate::p2p::network::client::IrohClient;
    use crate::p2p::network::config::ClientConfig;
    use crate::sql::ExecResult;
    use crate::sql::engine::Session;
    use tempfile::TempDir;

    async fn node() -> (GuardianDB, TempDir) {
        let temp = TempDir::new().unwrap();
        let mut cfg = ClientConfig::testing();
        cfg.data_store_path = Some(temp.path().join("iroh"));
        cfg.port = 0;
        let iroh = IrohClient::new(cfg).await.unwrap();
        let opts = NewGuardianDBOptions {
            directory: Some(temp.path().join("guardian")),
            backend: Some(iroh.backend().clone()),
            ..Default::default()
        };
        let db = GuardianDB::new(iroh.clone(), Some(opts)).await.unwrap();
        (db, temp)
    }

    fn rows(r: &ExecResult) -> &Vec<Vec<crate::sql::SqlValue>> {
        match r {
            ExecResult::Rows { rows, .. } => rows,
            ExecResult::Command { tag } => panic!("expected rows, got {tag}"),
        }
    }

    #[tokio::test]
    async fn sql_over_guardiandb_document_store() {
        let (db, _tmp) = node().await;
        let database = open_sql(&db, "app").await.unwrap();
        let mut s = Session::new(database, "guardian");

        s.execute(
            "CREATE TABLE users (id INT PRIMARY KEY, email TEXT UNIQUE NOT NULL, data JSONB)",
        )
        .await
        .unwrap();
        s.execute("INSERT INTO users (id, email, data) VALUES (1, 'a@x.com', '{\"plan\":\"pro\"}'), (2, 'b@x.com', '{}')")
            .await
            .unwrap();

        let mut r = s
            .execute("SELECT id, email FROM users ORDER BY id")
            .await
            .unwrap();
        let r = r.pop().unwrap();
        assert_eq!(rows(&r).len(), 2);
        assert_eq!(rows(&r)[0][1].to_text().unwrap(), "a@x.com");

        // Unique enforcement works over the document store.
        let err = s
            .execute("INSERT INTO users VALUES (3, 'a@x.com', '{}')")
            .await
            .unwrap_err();
        assert_eq!(err.sqlstate(), "23505");

        // Update + delete persist to the document store.
        s.execute("UPDATE users SET email = 'a2@x.com' WHERE id = 1")
            .await
            .unwrap();
        s.execute("DELETE FROM users WHERE id = 2").await.unwrap();
        let mut r = s.execute("SELECT count(*) FROM users").await.unwrap();
        assert_eq!(rows(&r.pop().unwrap())[0][0].to_text().unwrap(), "1");
    }

    #[tokio::test]
    async fn catalog_and_data_persist_across_reopen() {
        let temp = TempDir::new().unwrap();
        let mut cfg = ClientConfig::testing();
        cfg.data_store_path = Some(temp.path().join("iroh"));
        cfg.port = 0;
        let iroh = IrohClient::new(cfg).await.unwrap();
        let guardian_dir = temp.path().join("guardian");
        let make_opts = || NewGuardianDBOptions {
            directory: Some(guardian_dir.clone()),
            backend: Some(iroh.backend().clone()),
            ..Default::default()
        };

        // First backend: create schema + data.
        {
            let db = GuardianDB::new(iroh.clone(), Some(make_opts()))
                .await
                .unwrap();
            let database = open_sql(&db, "app").await.unwrap();
            let mut s = Session::new(database, "guardian");
            s.execute("CREATE TABLE t (id INT PRIMARY KEY, v TEXT)")
                .await
                .unwrap();
            s.execute("INSERT INTO t VALUES (1, 'persisted')")
                .await
                .unwrap();
        }

        // Second backend opening the same document store sees the same data via
        // a fresh relational view (catalog + rows reload from storage).
        {
            let db = GuardianDB::new(iroh.clone(), Some(make_opts()))
                .await
                .unwrap();
            let database = open_sql(&db, "app").await.unwrap();
            let mut s = Session::new(database, "guardian");
            let mut r = s.execute("SELECT v FROM t WHERE id = 1").await.unwrap();
            assert_eq!(
                rows(&r.pop().unwrap())[0][0].to_text().unwrap(),
                "persisted"
            );
        }
    }
}
