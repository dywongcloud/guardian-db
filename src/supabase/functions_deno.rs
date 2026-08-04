//! Deno-based execution for "regular" (non-WASM) Supabase Edge Functions.
//!
//! Real Supabase Edge Functions are plain Deno TypeScript/JavaScript —
//! `Deno.serve((req) => new Response(...))` — not a compiled artifact. This
//! module gives deployed function bodies that *aren't* WebAssembly (see
//! [`super::functions::FunctionRuntime::Deno`]) a runtime substrate that
//! needs no `compute`/wasmtime feature at all: it shells out to a `deno`
//! binary already on the host's `PATH` (or `$GDB_DENO_PATH`), exactly the
//! substrate Supabase's own CLI (`supabase functions serve`) uses for local
//! development.
//!
//! ## Process shape
//!
//! Every invocation is a **fresh subprocess** — no state, no warm pool,
//! mirroring the WASM path's "every run gets a fresh `Store`" isolation
//! (the honest trade-off: a cold Deno start costs tens of milliseconds,
//! same class as this project's other supervised-child-process runtimes,
//! e.g. `compute-llm-colibri`; a pooled/warm long-lived runtime is a later
//! optimisation, not a correctness requirement).
//!
//! The child runs [`HARNESS_SCRIPT`] (embedded at compile time), which
//! imports the deployed function, intercepts `Deno.serve` to capture the
//! handler instead of binding a port, builds a real `Request` from the
//! envelope piped over stdin, and writes exactly one JSON value to stdout:
//! either the response envelope or a typed `{__gdb_error_kind, message}`.
//!
//! ## Sandbox
//!
//! Deno is secure-by-default (no ambient authority), and every grant here is
//! as narrow as the harness's own needs, mirroring the WASM path's
//! `HostGrants` philosophy (nothing but `gdb.log` linked in by default):
//!
//! * `--allow-net` — outbound `fetch`, matching real Supabase Edge Functions
//!   (their whole point is usually to call another API). Not currently
//!   scoped to an allowlist; a later slice could add one.
//! * `--allow-env=<names>` — exactly the function's own `functions.secrets`
//!   names, nothing else. The child's *process* environment is cleared
//!   (`env_clear`) and rebuilt from scratch with only `PATH`, `HOME`,
//!   `DENO_DIR` and those secrets, so even a permission-check bug has
//!   nothing ambient to read.
//! * `--allow-read` / `--allow-write` — scoped to the per-invocation scratch
//!   directory (harness + staged function source) and the shared
//!   `DENO_DIR` module cache. No other path is reachable.
//! * No `--allow-run`, `--allow-ffi`, or `--allow-sys` — ever.
//!
//! `console.*` output is redirected to stderr by the harness and forwarded
//! into `tracing` here — the `gdb.log` equivalent for this runtime.
//! Wall-clock is bounded by [`tokio::time::timeout`]; the child is killed on
//! expiry (`kill_on_drop`). Memory is bounded (best-effort — V8's heap, not
//! an OS cgroup) via `--v8-flags=--max-old-space-size`.

use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;

use serde::Deserialize;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;

use crate::supabase::functions::{GuestError, InvocationInput, InvocationOutput};

/// The guest harness, embedded at compile time so the binary is fully
/// self-contained (no data file to ship alongside `guardian-supabase`).
const HARNESS_SCRIPT: &str = include_str!("functions_deno_harness.ts");

/// Ceiling on captured stdout — a defensive backstop against a runaway
/// handler; in practice `--v8-flags=--max-old-space-size` bounds the
/// response long before this triggers.
const MAX_OUTPUT_BYTES: usize = 64 * 1024 * 1024;

/// The harness's error-shaped stdout value.
#[derive(Debug, Deserialize)]
struct HarnessError {
    __gdb_error_kind: String,
    message: String,
}

/// Run a deployed Deno function body against `input`, returning its response
/// envelope. `timeout_ms` bounds wall-clock; `memory_bytes` bounds the V8
/// heap.
pub(crate) async fn run_deno_guest(
    source: &[u8],
    input: &InvocationInput,
    timeout_ms: u64,
    memory_bytes: u64,
) -> Result<InvocationOutput, GuestError> {
    let source_text = std::str::from_utf8(source)
        .map_err(|e| GuestError::Boot(format!("function source is not valid UTF-8: {e}")))?;

    let scratch = std::env::temp_dir().join(format!("gdb-fn-{}", uuid::Uuid::new_v4()));
    tokio::fs::create_dir_all(&scratch)
        .await
        .map_err(|e| GuestError::Boot(format!("failed to create scratch directory: {e}")))?;
    let _cleanup = ScratchGuard(scratch.clone());

    let user_path = scratch.join("function.ts");
    let harness_path = scratch.join("harness.ts");
    tokio::fs::write(&user_path, source_text)
        .await
        .map_err(|e| GuestError::Boot(format!("failed to stage function source: {e}")))?;
    tokio::fs::write(&harness_path, HARNESS_SCRIPT)
        .await
        .map_err(|e| GuestError::Boot(format!("failed to stage guest harness: {e}")))?;

    let deno_dir = deno_cache_dir();
    tokio::fs::create_dir_all(&deno_dir)
        .await
        .map_err(|e| GuestError::Boot(format!("failed to create deno cache directory: {e}")))?;

    let output = spawn_and_run(
        &harness_path,
        &user_path,
        &scratch,
        &deno_dir,
        input,
        timeout_ms,
        memory_bytes,
    )
    .await?;

    for line in String::from_utf8_lossy(&output.stderr).lines() {
        let line = line.trim();
        if !line.is_empty() {
            tracing::info!(target: "guardian_db::supabase::functions::deno", "{line}");
        }
    }

    if !output.status.success() {
        let tail = tail_lines(&output.stderr, 20);
        return Err(GuestError::Boot(format!(
            "deno exited with {}: {}",
            output.status,
            if tail.is_empty() {
                "(no output)".to_string()
            } else {
                tail
            }
        )));
    }

    if output.stdout.len() > MAX_OUTPUT_BYTES {
        return Err(GuestError::Runtime(format!(
            "response exceeds {MAX_OUTPUT_BYTES} bytes"
        )));
    }

    if let Ok(err) = serde_json::from_slice::<HarnessError>(&output.stdout) {
        return Err(match err.__gdb_error_kind.as_str() {
            "boot" => GuestError::Boot(err.message),
            _ => GuestError::Runtime(err.message),
        });
    }

    serde_json::from_slice::<InvocationOutput>(&output.stdout).map_err(|e| {
        GuestError::Runtime(format!(
            "invalid output from deno harness: {e} (stdout: {})",
            String::from_utf8_lossy(&output.stdout)
        ))
    })
}

#[allow(clippy::too_many_arguments)]
async fn spawn_and_run(
    harness_path: &std::path::Path,
    user_path: &std::path::Path,
    scratch: &std::path::Path,
    deno_dir: &std::path::Path,
    input: &InvocationInput,
    timeout_ms: u64,
    memory_bytes: u64,
) -> Result<std::process::Output, GuestError> {
    let deno_bin = std::env::var("GDB_DENO_PATH").unwrap_or_else(|_| "deno".to_string());
    let allowed_env: Vec<&str> = input.env.iter().map(|(k, _)| k.as_str()).collect();
    let max_old_space_mb = (memory_bytes / (1024 * 1024)).max(16);

    let mut cmd = Command::new(&deno_bin);
    cmd.arg("run")
        .arg("--quiet")
        .arg("--no-check")
        .arg("--no-prompt")
        .arg(format!(
            "--allow-read={},{}",
            scratch.display(),
            deno_dir.display()
        ))
        .arg(format!("--allow-write={}", deno_dir.display()))
        .arg("--allow-net")
        .arg(format!(
            "--v8-flags=--max-old-space-size={max_old_space_mb}"
        ));
    if !allowed_env.is_empty() {
        cmd.arg(format!("--allow-env={}", allowed_env.join(",")));
    }
    cmd.arg(harness_path)
        .arg(user_path)
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("HOME", std::env::var("HOME").unwrap_or_default())
        .env("DENO_DIR", deno_dir)
        .env("DENO_NO_UPDATE_CHECK", "1")
        .env("NO_COLOR", "1")
        .envs(input.env.iter().cloned())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);

    let mut child = cmd.spawn().map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            GuestError::Boot(format!(
                "deno runtime not found on PATH (looked for \"{deno_bin}\"); install Deno \
                 (https://deno.land) or set GDB_DENO_PATH to invoke non-WASM Edge Functions"
            ))
        } else {
            GuestError::Boot(format!("failed to spawn deno: {e}"))
        }
    })?;

    let envelope = serde_json::to_vec(input)
        .map_err(|e| GuestError::Runtime(format!("input envelope encode: {e}")))?;
    {
        let stdin = child.stdin.as_mut().expect("stdin was configured as piped");
        stdin
            .write_all(&envelope)
            .await
            .map_err(|e| GuestError::Runtime(format!("failed writing input to deno: {e}")))?;
        stdin.shutdown().await.ok();
    }

    match tokio::time::timeout(Duration::from_millis(timeout_ms), child.wait_with_output()).await {
        Ok(Ok(output)) => Ok(output),
        Ok(Err(e)) => Err(GuestError::Runtime(format!("deno process error: {e}"))),
        // The `Child` (and its `kill_on_drop`) is moved into the timed-out
        // future above; dropping it here on expiry kills the process.
        Err(_) => Err(GuestError::Runtime("wall-clock deadline exceeded".into())),
    }
}

/// The shared, cross-invocation Deno module cache — set as `DENO_DIR` so
/// remote imports the deployed function makes are fetched once, not on
/// every single invocation.
fn deno_cache_dir() -> PathBuf {
    std::env::temp_dir().join("guardian-db-deno-cache")
}

fn tail_lines(bytes: &[u8], n: usize) -> String {
    let text = String::from_utf8_lossy(bytes);
    let lines: Vec<&str> = text.lines().filter(|l| !l.trim().is_empty()).collect();
    let start = lines.len().saturating_sub(n);
    lines[start..].join("\n")
}

/// Best-effort cleanup of the per-invocation scratch directory. Deploy
/// bodies never contain secrets (that's `functions.secrets`, injected via
/// process env, never written to disk), so a failed cleanup leaks nothing
/// sensitive — it just litters the temp directory, which the OS reclaims.
struct ScratchGuard(PathBuf);

impl Drop for ScratchGuard {
    fn drop(&mut self) {
        let path = self.0.clone();
        tokio::spawn(async move {
            let _ = tokio::fs::remove_dir_all(&path).await;
        });
    }
}
