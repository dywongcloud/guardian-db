//! Distributed conformance: PostgreSQL-style SQL over two replicating GuardianDB
//! peers. Schema (catalog) and row writes made via SQL on one peer become
//! visible via SQL on the other after replication.
//!
//! Enabled by the `sql` feature: `cargo test --features sql --test sql_replication`.
#![cfg(feature = "sql")]

mod common;

use common::{TestNode, connect_nodes, wait_for_propagation};
use guardian_db::sql::engine::{ChangeEvent, Session};
use guardian_db::sql::open_sql;
use guardian_db::sql::{ChangeOp, ChangeSource, ExecResult};
use std::time::Duration;
use tokio::sync::mpsc::UnboundedReceiver;

/// Wait (up to 5s) for a `ChangeEvent` on `rx`. The replicated-write bridge
/// (`crate::sql::guardian_storage::spawn_replication_bridge`) runs in its own
/// spawned task, relaying diffs from a broadcast channel into this one; under
/// the single-threaded `#[tokio::test]` runtime that task only gets a chance
/// to run when the current task yields, so — unlike the local-commit path,
/// which delivers synchronously within the `Session::execute` call — a
/// replicated event is not necessarily pending yet the instant `refresh()`
/// returns. An `.await`ed timeout gives the bridge task that chance.
async fn recv_change(rx: &mut UnboundedReceiver<ChangeEvent>) -> ChangeEvent {
    tokio::time::timeout(Duration::from_secs(5), rx.recv())
        .await
        .expect("timed out waiting for a ChangeEvent")
        .expect("change-event channel closed unexpectedly")
}

/// Assert no `ChangeEvent` arrives on `rx` within a short window.
async fn assert_no_change(rx: &mut UnboundedReceiver<ChangeEvent>) {
    if let Ok(got) = tokio::time::timeout(Duration::from_millis(300), rx.recv()).await {
        panic!("unexpected ChangeEvent: {got:?}");
    }
}

fn rows(r: ExecResult) -> Vec<Vec<String>> {
    match r {
        ExecResult::Rows { rows, .. } => rows
            .into_iter()
            .map(|row| {
                row.into_iter()
                    .map(|v| v.to_text().unwrap_or_default())
                    .collect()
            })
            .collect(),
        ExecResult::Command { tag } => panic!("expected rows, got {tag}"),
    }
}

// Distributed-conformance target. Raw document replication between two peers
// works (see tests/integration_replication.rs), but making the *relational*
// view (catalog + rows) converge deterministically across peers additionally
// requires (a) the two `open_sql` document stores to share an iroh-docs
// namespace and (b) the relational engine to observe background replication
// (the local index updates on `refresh()`/load, not automatically). This is the
// same in-progress distributed-coordination work tracked for strict mode in
// docs/postgres-compat.md. Run with `--ignored` to exercise the intended flow.
#[tokio::test]
#[ignore = "distributed SQL replication: requires shared-namespace stores + background index refresh (in progress)"]
async fn sql_schema_and_rows_replicate_across_two_peers() {
    let node1 = TestNode::new("sql_repl_a").await.expect("node1");
    let node2 = TestNode::new("sql_repl_b").await.expect("node2");
    connect_nodes(&node1, &node2).await.expect("connect");

    // Both peers open the same logical relational database (shared document store).
    let db1 = open_sql(&node1.db, "shared-app").await.expect("open db1");
    let db2 = open_sql(&node2.db, "shared-app").await.expect("open db2");
    wait_for_propagation().await;

    // Peer 1 creates the schema and inserts rows via SQL.
    let mut s1 = Session::new(db1, "guardian");
    s1.execute("CREATE TABLE users (id INT PRIMARY KEY, name TEXT NOT NULL)")
        .await
        .expect("create table");
    s1.execute("INSERT INTO users VALUES (1, 'Alice'), (2, 'Bob')")
        .await
        .expect("insert");

    // Drive bidirectional synchronization.
    node1
        .db
        .connect_to_peer(node2.iroh.node_id())
        .await
        .expect("n1->n2");
    node2
        .db
        .connect_to_peer(node1.iroh.node_id())
        .await
        .expect("n2->n1");
    wait_for_propagation().await;
    wait_for_propagation().await;

    // Re-sync peer 2's local index from the replicated documents, then read.
    db2.storage().refresh().await.expect("refresh peer 2 index");

    // Peer 2 sees the replicated schema and rows through a fresh SQL session.
    let mut s2 = Session::new(db2.clone(), "guardian");
    let mut r = s2
        .execute("SELECT id, name FROM users ORDER BY id")
        .await
        .expect("select on peer 2");
    let grid = rows(r.pop().unwrap());
    assert_eq!(grid.len(), 2, "peer 2 should see both replicated rows");
    assert_eq!(grid[0][1], "Alice");
    assert_eq!(grid[1][1], "Bob");
}

// ===========================================================================
// Replicated-write realtime bridge (Phase E): single-node, no real two-node
// networking. `Database::subscribe_changes` only observes local commits made
// through a `Session`; writes that arrive via P2P replication land in the
// document store's index correctly but are otherwise invisible to that hook.
// `GuardianDBDocumentStore::refresh_doc_index` (driven here by
// `GuardianRelationalStorage::refresh`) diffs foreign-authored index changes
// against the previous snapshot and bridges them into the same
// `ChangeEvent` channel, tagged `ChangeSource::Replicated`.
//
// A second `AuthorId` on the *same* iroh-docs namespace, writing directly
// through `WillowDocs` (bypassing the relational engine entirely), stands in
// for a peer's replicated entry — same-node different-author writes are
// classified by iroh as `InsertLocal`, not `InsertRemote`, so only the
// polling `refresh()` path (not the reactive live-sync task) exercises the
// new author-based diff detection; that's why this test drives `refresh()`
// explicitly instead of waiting on background sync.
#[tokio::test]
async fn replicated_document_writes_surface_as_change_events() {
    let node = TestNode::new("sql_repl_bridge").await.expect("node");
    let database = open_sql(&node.db, "app").await.expect("open db");

    // Subscribe before any row writes so the local INSERT below is also
    // observed on this channel (proving local delivery still works
    // unchanged) and so we have a receiver ready before fabricating the
    // foreign-authored writes.
    let mut rx = database.subscribe_changes();

    let mut s = Session::new(database.clone(), "guardian");
    s.execute("CREATE TABLE t (id INT PRIMARY KEY, v TEXT)")
        .await
        .expect("create table");
    s.execute("INSERT INTO t VALUES (1, 'local')")
        .await
        .expect("insert local row");

    let local_ev = recv_change(&mut rx).await;
    assert_eq!(local_ev.op, ChangeOp::Insert);
    assert_eq!(local_ev.source, ChangeSource::Local);
    assert_eq!(local_ev.new.as_ref().unwrap()["v"], "local");
    assert_no_change(&mut rx).await;

    // Recover the wrapped-doc template (`{"_id","__collection","doc"}`) and
    // the row's document-store key for the real row from the store's
    // synchronous index, so the fabricated rows below are byte-for-byte
    // structurally correct without hand-encoding the engine's row JSON shape.
    let doc_store = database.storage().document_store();
    let index = doc_store.index();
    let template_key = index
        .keys()
        .expect("index keys")
        .into_iter()
        .find(|k| !k.starts_with("__gdb_sql_catalog"))
        .expect("row key present in index");
    let template_bytes = index
        .get_bytes(&template_key)
        .expect("index get_bytes")
        .expect("row bytes present in index");
    let template: serde_json::Value =
        serde_json::from_slice(&template_bytes).expect("valid wrapped-doc json");
    let collection = template["__collection"]
        .as_str()
        .expect("__collection present")
        .to_string();

    // Build a wrapped-doc (key, value) pair for a foreign row, cloning the
    // real row's `doc` payload (so `__table`/`__schema` markers match) and
    // overriding just the row id and the `v` column.
    let make_row = |row_id: &str, v: &str| -> (Vec<u8>, Vec<u8>) {
        let gkey = format!("{collection}\u{1f}{row_id}");
        let mut row = template["doc"].clone();
        row["_id"] = serde_json::json!(row_id);
        row["id"] = serde_json::json!(2);
        row["v"] = serde_json::json!(v);
        let wrapped = serde_json::json!({
            "_id": gkey,
            "__collection": collection,
            "doc": row,
        });
        (
            gkey.into_bytes(),
            serde_json::to_vec(&wrapped).expect("serialize wrapped doc"),
        )
    };

    // A second AuthorId on the SAME namespace, standing in for a replicating
    // peer. The namespace id is recovered from the store's persisted cache
    // (the same mechanism `GuardianDBDocumentStore::new` uses to reopen its
    // own document across restarts).
    let namespace_id = {
        let cache = doc_store.cache();
        let bytes = cache
            .get(b"_iroh_docs_doc_namespace_id")
            .await
            .expect("cache get")
            .expect("namespace id persisted in cache");
        let mut ns = [0u8; 32];
        assert_eq!(bytes.len(), 32, "namespace id is 32 bytes");
        ns.copy_from_slice(&bytes);
        iroh_docs::NamespaceId::from(ns)
    };
    let willow = node
        .iroh
        .docs_client()
        .await
        .expect("iroh-docs client available");
    let doc = willow
        .open_doc(namespace_id)
        .await
        .expect("open doc")
        .expect("doc exists for this namespace");
    let foreign_author = willow
        .docs()
        .author_create()
        .await
        .expect("create second author");

    // ---- INSERT: a brand-new foreign-authored row. ----
    let (key_bytes, value_bytes) = make_row("foreign-1", "from-peer");
    willow
        .set_bytes(&doc, foreign_author, key_bytes.clone(), value_bytes)
        .await
        .expect("fabricate foreign insert");
    database
        .storage()
        .refresh()
        .await
        .expect("refresh after foreign insert");

    let ev = recv_change(&mut rx).await;
    assert_eq!(ev.op, ChangeOp::Insert);
    assert_eq!(ev.source, ChangeSource::Replicated);
    assert!(ev.old.is_none());
    assert_eq!(ev.new.as_ref().unwrap()["v"], "from-peer");
    assert_no_change(&mut rx).await;

    // ---- refresh() with no new foreign writes must not emit a spurious
    // event (the diff against the unchanged index is empty). ----
    database.storage().refresh().await.expect("idle refresh");
    assert_no_change(&mut rx).await;

    // ---- UPDATE: the same foreign author overwrites the same key. ----
    let (_, value_bytes2) = make_row("foreign-1", "from-peer-2");
    willow
        .set_bytes(&doc, foreign_author, key_bytes.clone(), value_bytes2)
        .await
        .expect("fabricate foreign update");
    database
        .storage()
        .refresh()
        .await
        .expect("refresh after foreign update");

    let ev = recv_change(&mut rx).await;
    assert_eq!(ev.op, ChangeOp::Update);
    assert_eq!(ev.source, ChangeSource::Replicated);
    assert_eq!(ev.old.as_ref().unwrap()["v"], "from-peer");
    assert_eq!(ev.new.as_ref().unwrap()["v"], "from-peer-2");
    assert_no_change(&mut rx).await;

    // ---- DELETE: the same foreign author tombstones the key. ----
    willow
        .del(&doc, foreign_author, key_bytes.clone())
        .await
        .expect("fabricate foreign delete");
    database
        .storage()
        .refresh()
        .await
        .expect("refresh after foreign delete");

    let ev = recv_change(&mut rx).await;
    assert_eq!(ev.op, ChangeOp::Delete);
    assert_eq!(ev.source, ChangeSource::Replicated);
    assert_eq!(ev.old.as_ref().unwrap()["v"], "from-peer-2");
    assert!(ev.new.is_none());
    assert_no_change(&mut rx).await;
}
