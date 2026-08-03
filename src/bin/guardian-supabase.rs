//! The `guardian-supabase` gateway binary.
//!
//! Serves a Supabase-compatible HTTP surface (Kong-shaped `/rest/v1`,
//! `/auth/v1`, ...) over the GuardianDB SQL engine. By default it binds
//! `127.0.0.1:54321` (Supabase's local port) using an in-memory relational
//! store; pass `--path` to back it with a persistent, Iroh-replicated GuardianDB
//! node.
//!
//! On startup it prints `SUPABASE_URL`, `ANON_KEY` and `SERVICE_ROLE_KEY`
//! (and, when generated, the `JWT_SECRET`) so `supabase-js` can be pointed at
//! it directly:
//!
//! ```ts
//! import { createClient } from "@supabase/supabase-js";
//! const supabase = createClient("http://127.0.0.1:54321", ANON_KEY);
//! await supabase.from("todos").select("*");
//! ```

use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use tokio::net::TcpListener;

use guardian_db::guardian::GuardianDB;
use guardian_db::guardian::core::NewGuardianDBOptions;
use guardian_db::p2p::network::client::IrohClient;
use guardian_db::p2p::network::config::ClientConfig;
use guardian_db::sql::MemoryStorage;
use guardian_db::sql::engine::Database;
use guardian_db::sql::{RelationalStorage, open_sql};
use guardian_db::supabase::mailer::MailerConfig;
use guardian_db::supabase::project::{ProjectKeys, Secret, generate_jwt_secret};
use guardian_db::supabase::{AppState, ServiceConfig, SupabaseCompatProject, build_router};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let mut addr = "127.0.0.1:54321".to_string();
    let mut database = "app".to_string();
    let mut jwt_secret: Option<String> = None;
    let mut data_path: Option<String> = None;
    let mut functions_upstream: Option<String> = None;
    let mut mailer_url: Option<String> = None;
    let mut mailer_auth: Option<String> = None;
    let mut mailer_log = false;
    let mut require_email_confirmation = false;
    let mut otp_exp: Option<i64> = None;

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--addr" | "-a" => addr = args.next().unwrap_or(addr),
            "--database" | "-d" => database = args.next().unwrap_or(database),
            "--jwt-secret" => jwt_secret = args.next(),
            "--path" | "-p" => data_path = args.next(),
            "--functions-upstream" => functions_upstream = args.next(),
            "--mailer-url" => mailer_url = args.next(),
            // Never logged, printed, or included in any banner — only ever
            // forwarded as the `authorization` header of the mail webhook
            // request itself.
            "--mailer-auth" => mailer_auth = args.next(),
            "--mailer-log" => mailer_log = true,
            "--require-email-confirmation" => require_email_confirmation = true,
            "--otp-exp" => match args.next().and_then(|s| s.parse::<i64>().ok()) {
                Some(v) => otp_exp = Some(v),
                None => {
                    eprintln!("error: --otp-exp requires a numeric argument (seconds)");
                    std::process::exit(1);
                }
            },
            "--help" | "-h" => {
                print_help();
                return Ok(());
            }
            other => eprintln!("ignoring unknown argument: {other}"),
        }
    }

    if mailer_auth.is_some() && mailer_url.is_none() {
        eprintln!("error: --mailer-auth requires --mailer-url");
        std::process::exit(1);
    }
    if mailer_log && mailer_url.is_some() {
        eprintln!("error: --mailer-log and --mailer-url are mutually exclusive");
        std::process::exit(1);
    }
    let mailer = match mailer_url {
        Some(url) => MailerConfig::Http {
            url,
            authorization: mailer_auth.map(Secret::new),
        },
        None if mailer_log => MailerConfig::Log,
        None => MailerConfig::default(),
    };

    // Derive the project keys. A generated secret is printed once on startup.
    let (secret, generated) = match jwt_secret {
        Some(s) => (s, false),
        None => (generate_jwt_secret(), true),
    };
    let keys = ProjectKeys::from_secret(&secret, Utc::now().timestamp())?;
    let api_url = format!("http://{addr}");
    let anon_key = keys.anon_key.clone();
    let service_role_key = keys.service_role_key.clone();
    let project = SupabaseCompatProject::shell(&database, &api_url, keys, Utc::now());
    let mut config = ServiceConfig {
        functions_upstream,
        mailer,
        require_email_confirmation,
        ..ServiceConfig::default()
    };
    if let Some(exp) = otp_exp {
        config.mailer_otp_exp = exp;
    }

    print_banner(
        &api_url,
        &anon_key,
        &service_role_key,
        generated.then_some(secret.as_str()),
    );

    match data_path {
        Some(path) => {
            // Persistent, Iroh-backed GuardianDB node.
            let client = IrohClient::new(ClientConfig::development().with_data_path(&path)).await?;
            let node_id = client.id().await?.id;
            let db = GuardianDB::new(
                client,
                Some(NewGuardianDBOptions {
                    directory: Some(format!("{path}/guardian").into()),
                    ..Default::default()
                }),
            )
            .await?;
            let database_sql = open_sql(&db, &database).await?;

            // Keep the local relational view fresh as peers replicate in.
            let storage = database_sql.storage().clone();
            tokio::spawn(async move {
                loop {
                    tokio::time::sleep(Duration::from_secs(2)).await;
                    let _ = storage.refresh().await;
                }
            });

            println!("  storage : GuardianDB (Iroh, replicated) under {path}");
            println!("  node id : {node_id}   (share with peers to replicate)");
            serve(database_sql, project, config, &addr).await?;
        }
        None => {
            println!("  storage : in-memory (non-persistent) — pass --path for a replicated node");
            let database_sql = Arc::new(Database::new(Arc::new(MemoryStorage::new()), database));
            serve(database_sql, project, config, &addr).await?;
        }
    }
    Ok(())
}

async fn serve<S: RelationalStorage + 'static>(
    db: Arc<Database<S>>,
    project: SupabaseCompatProject,
    config: ServiceConfig,
    addr: &str,
) -> std::io::Result<()> {
    let state = AppState::new(db, project, config);
    let app = build_router(state);
    let listener = TcpListener::bind(addr).await?;
    println!("\nguardian-supabase listening on http://{addr}\n");
    axum::serve(listener, app.into_make_service()).await
}

fn print_banner(api_url: &str, anon_key: &str, service_role_key: &str, secret: Option<&str>) {
    println!("guardian-supabase — Supabase-compatible gateway for GuardianDB\n");
    println!("  SUPABASE_URL      : {api_url}");
    println!("  ANON_KEY          : {anon_key}");
    println!("  SERVICE_ROLE_KEY  : {service_role_key}");
    if let Some(secret) = secret {
        println!("  JWT_SECRET        : {secret}   (generated — save this to reuse the keys)");
    }
}

fn print_help() {
    println!(
        "guardian-supabase — Supabase-compatible gateway for GuardianDB\n\n\
         Usage: guardian-supabase [--addr 127.0.0.1:54321] [--database app] \
         [--jwt-secret <secret>] [--path <dir>] [--functions-upstream <url>]\n\
         [--mailer-url <url>] [--mailer-auth <value>] [--mailer-log] \
         [--require-email-confirmation] [--otp-exp <secs>]\n\n\
         Without --path, an in-memory store is used (great for development).\n\
         With --path, a persistent Iroh-replicated GuardianDB node backs the gateway.\n\n\
         Without --functions-upstream, /functions/v1 serves SQL-backed edge functions\n\
         from the supabase_functions.functions registry (see docs). With\n\
         --functions-upstream <url>, every /functions/v1 request (including OPTIONS\n\
         and unknown slugs) is forwarded verbatim to a self-hosted Supabase Edge\n\
         Runtime at <url> instead.\n\n\
         Email (signup confirmation / recovery / magic link):\n\
         --mailer-url <url>      POST a generic JSON envelope to this webhook for every\n\
         \x20                        outgoing email (the production transport).\n\
         --mailer-auth <value>   Authorization header value sent with --mailer-url\n\
         \x20                        requests (e.g. \"Bearer ...\"). Requires --mailer-url;\n\
         \x20                        never printed or logged.\n\
         --mailer-log             Write outgoing emails (including the verification URL)\n\
         \x20                        to the trace log instead. Development only; mutually\n\
         \x20                        exclusive with --mailer-url.\n\
         --require-email-confirmation\n\
         \x20                        Require clicking the emailed confirmation link before\n\
         \x20                        a new signup can sign in (default: auto-confirmed).\n\
         --otp-exp <secs>         How long a confirmation/recovery/magic-link token stays\n\
         \x20                        valid (default 3600).\n\
         Without --mailer-url/--mailer-log, no mailer transport is configured: any flow\n\
         that needs to send email (signup with --require-email-confirmation, /recover,\n\
         /otp, /magiclink, /resend) fails with a typed error instead of a silent no-op.\n\n\
         Point supabase-js at http://<addr> with the printed ANON_KEY."
    );
}
