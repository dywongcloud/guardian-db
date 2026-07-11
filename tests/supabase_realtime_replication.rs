//! Integration tests proving realtime `postgres_changes` delivery for
//! replicated (remote-authored) row changes, not just local commits.
//!
//! `Database::subscribe_changes` only observes commits made through a
//! `Session` on this node; peer-authored writes that arrive via P2P
//! replication land in the document store correctly but are otherwise
//! invisible to it. The Phase E bridge
//! (`guardian_db::sql::open_sql`/`open_sql_with`, internally
//! `spawn_replication_bridge`) diffs foreign-authored document-store index
//! changes and re-delivers them through the same `ChangeEvent` channel
//! (`ChangeSource::Replicated`), which `crate::supabase::realtime` already
//! serves generically. This test drives that whole pipeline end to end over
//! a real websocket, against a persistent/Iroh-backed `GuardianDBDocumentStore`
//! (not `MemoryStorage`, since the replication bridge only exists for
//! GuardianDB-backed SQL databases).
//!
//! Because same-node different-author writes are classified by iroh-docs as
//! `InsertLocal` (not `InsertRemote`), the reactive live-sync task never
//! fires for the fabricated write below; the test drives the diff
//! deterministically via `GuardianRelationalStorage::refresh` instead (see
//! `tests/sql_replication.rs` for the same technique in more detail).
#![cfg(feature = "supabase")]

mod common;

use std::time::Duration;

use common::TestNode;
use futures::{SinkExt, StreamExt};
use serde_json::{Value, json};
use tokio_tungstenite::tungstenite::Message as WsMessage;

use guardian_db::sql::engine::Session;
use guardian_db::sql::open_sql;
use guardian_db::supabase::project::ProjectKeys;
use guardian_db::supabase::{AppState, ServiceConfig, SupabaseCompatProject, build_router};

const TEST_SECRET: &str = "integration-test-jwt-secret-value-0123456789";
const IAT: i64 = 1_700_000_000;

type WsStream =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

async fn spawn_server(app: axum::Router) -> std::net::SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app.into_make_service())
            .await
            .unwrap();
    });
    addr
}

async fn ws_connect(addr: std::net::SocketAddr, apikey: &str) -> WsStream {
    let url = format!("ws://{addr}/realtime/v1/websocket?apikey={apikey}&vsn=1.0.0");
    let (ws, _resp) = tokio_tungstenite::connect_async(url).await.unwrap();
    ws
}

async fn ws_send(ws: &mut WsStream, v: Value) {
    ws.send(WsMessage::Text(v.to_string().into()))
        .await
        .unwrap();
}

async fn ws_recv(ws: &mut WsStream, secs: u64) -> Option<Value> {
    loop {
        let msg = tokio::time::timeout(Duration::from_secs(secs), ws.next())
            .await
            .ok()??
            .ok()?;
        match msg {
            WsMessage::Text(t) => return serde_json::from_str(t.as_str()).ok(),
            WsMessage::Ping(_) | WsMessage::Pong(_) => continue,
            _ => return None,
        }
    }
}

/// Read frames until one with `event` arrives (object or Phoenix array
/// form), or time out.
async fn ws_recv_event(ws: &mut WsStream, event: &str, secs: u64) -> Option<Value> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(secs);
    while tokio::time::Instant::now() < deadline {
        let frame = ws_recv(ws, secs).await?;
        let ev = frame
            .get("event")
            .or_else(|| frame.get(3))
            .and_then(Value::as_str)
            .unwrap_or("");
        if ev == event {
            return Some(frame);
        }
    }
    None
}

fn join_frame(topic: &str, reference: &str, config: Value) -> Value {
    json!({
        "topic": topic,
        "event": "phx_join",
        "payload": { "config": config },
        "ref": reference,
        "join_ref": reference,
    })
}

/// A wrapped-doc `(key, value)` pair for a foreign-authored row, cloning a
/// real row's `doc` payload (recovered from the store's index) so the
/// `__table`/`__schema` markers match, and overriding just the row id and
/// the `v` column. Mirrors the technique in `tests/sql_replication.rs`.
fn make_row(template: &Value, collection: &str, row_id: &str, v: &str) -> (Vec<u8>, Vec<u8>) {
    let gkey = format!("{collection}\u{1f}{row_id}");
    let mut row = template["doc"].clone();
    row["_id"] = json!(row_id);
    row["id"] = json!(2);
    row["v"] = json!(v);
    let wrapped = json!({
        "_id": gkey,
        "__collection": collection,
        "doc": row,
    });
    (
        gkey.into_bytes(),
        serde_json::to_vec(&wrapped).expect("serialize wrapped doc"),
    )
}

#[tokio::test]
async fn replicated_write_delivers_postgres_changes_over_websocket() {
    let node = TestNode::new("supa_realtime_repl").await.expect("node");
    let db = open_sql(&node.db, "app").await.expect("open sql db");

    {
        let mut s = Session::new(db.clone(), "guardian");
        s.execute("CREATE TABLE t (id INT PRIMARY KEY, v TEXT)")
            .await
            .expect("create table");
        s.execute("INSERT INTO t VALUES (1, 'local')")
            .await
            .expect("insert local row (wrapped-doc template)");
    }

    let keys = ProjectKeys::from_secret(TEST_SECRET, IAT).unwrap();
    let anon = keys.anon_key.clone();
    let project =
        SupabaseCompatProject::shell("app", "http://127.0.0.1:54321", keys, chrono::Utc::now());
    let state = AppState::new(db.clone(), project, ServiceConfig::default());
    let app = build_router(state);
    let addr = spawn_server(app).await;

    let mut ws = ws_connect(addr, &anon).await;
    ws_send(
        &mut ws,
        join_frame(
            "realtime:public:t",
            "1",
            json!({"postgres_changes": [{"event": "*", "schema": "public", "table": "t"}]}),
        ),
    )
    .await;
    let reply = ws_recv_event(&mut ws, "phx_reply", 5)
        .await
        .expect("join reply");
    assert_eq!(reply["payload"]["status"], "ok", "{reply}");

    // Fabricate a foreign-authored row exactly as in
    // `tests/sql_replication.rs`: recover the real row's wrapped-doc
    // template from the document store's index, mint a second `AuthorId` on
    // the same iroh-docs namespace, and write directly through `WillowDocs`
    // (bypassing the relational engine and Session commit path entirely).
    let doc_store = db.storage().document_store();
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
    let template: Value = serde_json::from_slice(&template_bytes).expect("valid wrapped-doc json");
    let collection = template["__collection"]
        .as_str()
        .expect("__collection present")
        .to_string();

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

    let (_key_bytes, value_bytes) = make_row(&template, &collection, "foreign-1", "from-peer");
    willow
        .set_bytes(&doc, foreign_author, _key_bytes.clone(), value_bytes)
        .await
        .expect("fabricate foreign insert");

    // Deterministically trigger the diff (no reliance on the reactive
    // live-sync task or timers — see module doc comment).
    db.storage()
        .refresh()
        .await
        .expect("refresh after foreign insert");

    let ev = ws_recv_event(&mut ws, "postgres_changes", 5)
        .await
        .expect("postgres_changes frame for the replicated insert");
    let data = &ev["payload"]["data"];
    assert_eq!(data["type"], "INSERT");
    assert_eq!(data["eventType"], "INSERT");
    assert_eq!(data["schema"], "public");
    assert_eq!(data["table"], "t");
    assert_eq!(data["record"]["v"], "from-peer");
    assert_eq!(data["new"]["v"], "from-peer");
}
