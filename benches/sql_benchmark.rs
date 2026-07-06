#![cfg(feature = "sql")]
//! SQL performance benchmarks — establishes baselines for GuardianDB's
//! PostgreSQL-compatible query engine (SELECT, JOIN, GROUP BY, ORDER BY).

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use guardian_db::sql::engine::{Database, Session};
use guardian_db::sql::MemoryStorage;
use std::sync::Arc;
use tokio::runtime::Runtime;

/// Build a session with a table `t (id INT, val INT, cat INT)` pre-populated
/// with `n` rows.  Row values follow the same formula as the task spec so
/// that every benchmark runs against identical data:
///   id  = i
///   val = i * 7 % 10000  (pseudo-random, ~uniform 0-9999)
///   cat = i % 10         (10 distinct category values)
async fn setup_session(n: usize) -> Session<MemoryStorage> {
    let db = Arc::new(Database::new(Arc::new(MemoryStorage::new()), "bench"));
    let mut s = Session::new(db, "guardian");
    s.execute("CREATE TABLE t (id INT, val INT, cat INT)")
        .await
        .unwrap();
    for i in 0..n {
        s.execute(&format!(
            "INSERT INTO t VALUES ({i}, {}, {})",
            i * 7 % 10000,
            i % 10
        ))
        .await
        .unwrap();
    }
    s
}

// ── SELECT with WHERE ─────────────────────────────────────────────────────────

fn bench_select(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    // Point lookup: returns exactly 1 row (id = 5000).
    c.bench_function("select_point_lookup", |b| {
        b.iter(|| {
            rt.block_on(async {
                let mut s = setup_session(10_000).await;
                black_box(
                    s.execute(black_box("SELECT * FROM t WHERE id = 5000"))
                        .await
                        .unwrap(),
                )
            })
        })
    });

    // Range scan: val > 5000 matches ~50 % of rows (≈ 5 000 rows).
    c.bench_function("select_range_scan", |b| {
        b.iter(|| {
            rt.block_on(async {
                let mut s = setup_session(10_000).await;
                black_box(
                    s.execute(black_box("SELECT * FROM t WHERE val > 5000"))
                        .await
                        .unwrap(),
                )
            })
        })
    });
}

// ── JOIN ──────────────────────────────────────────────────────────────────────

fn bench_join(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    // INNER JOIN of two 1 000-row tables on the id column (all 1 000 rows match).
    c.bench_function("join_two_tables", |b| {
        b.iter(|| {
            rt.block_on(async {
                let db = Arc::new(Database::new(Arc::new(MemoryStorage::new()), "bench"));
                let mut s = Session::new(db, "guardian");
                s.execute("CREATE TABLE a (id INT, val INT)").await.unwrap();
                s.execute("CREATE TABLE b (id INT, val INT)").await.unwrap();
                for i in 0..1000_usize {
                    s.execute(&format!("INSERT INTO a VALUES ({i}, {})", i * 3 % 1000))
                        .await
                        .unwrap();
                    s.execute(&format!("INSERT INTO b VALUES ({i}, {})", i * 5 % 1000))
                        .await
                        .unwrap();
                }
                black_box(
                    s.execute(black_box("SELECT * FROM a JOIN b ON a.id = b.id"))
                        .await
                        .unwrap(),
                )
            })
        })
    });
}

// ── GROUP BY aggregate ────────────────────────────────────────────────────────

fn bench_group_by(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    // 10 000 rows → 10 groups; measures COUNT(*) + SUM aggregation.
    c.bench_function("group_by_aggregate", |b| {
        b.iter(|| {
            rt.block_on(async {
                let mut s = setup_session(10_000).await;
                black_box(
                    s.execute(black_box(
                        "SELECT cat, COUNT(*), SUM(val) FROM t GROUP BY cat",
                    ))
                    .await
                    .unwrap(),
                )
            })
        })
    });
}

// ── ORDER BY ──────────────────────────────────────────────────────────────────

fn bench_order_by(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    // Full-table sort of 10 000 rows descending by val.
    c.bench_function("order_by_desc", |b| {
        b.iter(|| {
            rt.block_on(async {
                let mut s = setup_session(10_000).await;
                black_box(
                    s.execute(black_box("SELECT * FROM t ORDER BY val DESC"))
                        .await
                        .unwrap(),
                )
            })
        })
    });
}

criterion_group!(benches, bench_select, bench_join, bench_group_by, bench_order_by);
criterion_main!(benches);
