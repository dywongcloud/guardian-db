//! Pluggable transactional email delivery for the GoTrue-compatible auth flows.
//!
//! Real Supabase (GoTrue) sends confirmation / recovery / magic-link emails
//! through an operator-configured SMTP relay. This gateway never dials SMTP
//! directly (no `lettre` dependency); instead a [`Mailer`] trait abstracts the
//! transport, with four implementations:
//!
//! - [`MemoryMailer`] — captures messages in-process (the default in tests, and
//!   useful for any deployment that wants to consume email out-of-band).
//! - [`HttpMailer`] — POSTs a generic JSON envelope to an operator-configured
//!   webhook URL (e.g. a small serverless function that forwards to Postmark,
//!   Resend, SendGrid, ...). This is the production transport.
//! - [`LogMailer`] — writes the message (including the verification URL) to
//!   the trace log. Strictly opt-in and meant for local development only: it
//!   deliberately violates the "no secret in logs" spirit for confirmation
//!   tokens, so it must never be a silent fallback.
//! - [`UnconfiguredMailer`] / [`UnsupportedMailer`] — typed failures. Every
//!   email-flow endpoint fails loudly (never a fake `200`) when no usable
//!   transport is configured.
//!
//! SMTP itself is out of scope for this slice: [`MailerConfig::Smtp`] exists so
//! configuration can express the intent, but [`build_mailer`] maps it to
//! [`UnsupportedMailer`], which returns [`MailError::TransportUnsupported`] —
//! rendered as a typed `501` by the caller, never silence.

use crate::supabase::project::Secret;
use async_trait::async_trait;
use std::sync::Arc;
use std::sync::Mutex;

/// A message ready to send. `html` and `text` are alternative renderings of
/// the same content; transports may use either or both.
#[derive(Clone, Debug)]
pub struct EmailMessage {
    pub to: String,
    pub subject: String,
    pub html: String,
    pub text: String,
    pub email_type: EmailType,
}

/// Which auth flow a message belongs to (informational; carried in the JSON
/// envelope [`HttpMailer`] sends so a webhook can route by type).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EmailType {
    Signup,
    Recovery,
    MagicLink,
}

impl EmailType {
    pub fn as_str(&self) -> &'static str {
        match self {
            EmailType::Signup => "signup",
            EmailType::Recovery => "recovery",
            EmailType::MagicLink => "magiclink",
        }
    }
}

/// Why a send failed. Never carries a token, password, or header value — only
/// enough detail to render a typed, secret-free error to the caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MailError {
    /// No usable transport is configured ([`MailerConfig::Unconfigured`]).
    NotConfigured,
    /// The configured transport exists but is not implemented in this slice
    /// (e.g. `"smtp"`).
    TransportUnsupported(&'static str),
    /// The transport attempted delivery and failed. The message is safe to
    /// surface (e.g. `"mail webhook returned 502"`) — never the message body,
    /// headers, or token.
    Send(String),
}

impl std::fmt::Display for MailError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MailError::NotConfigured => write!(f, "no mailer transport is configured"),
            MailError::TransportUnsupported(t) => {
                write!(f, "mailer transport {t:?} is not implemented")
            }
            MailError::Send(msg) => write!(f, "mail delivery failed: {msg}"),
        }
    }
}

impl std::error::Error for MailError {}

/// A transactional-email transport.
#[async_trait]
pub trait Mailer: Send + Sync {
    async fn send(&self, msg: EmailMessage) -> Result<(), MailError>;

    /// Whether this transport can actually deliver mail. `false` for
    /// [`UnconfiguredMailer`]; used by callers to fail a flow up front (before
    /// minting a token / mutating a row) rather than after.
    fn is_configured(&self) -> bool {
        true
    }
}

/// Captures every message in-process. The default transport for tests; also a
/// legitimate production choice for a deployment that polls / drains the
/// queue out-of-band via [`MemoryMailer::messages`].
#[derive(Default)]
pub struct MemoryMailer {
    messages: Mutex<Vec<EmailMessage>>,
}

impl MemoryMailer {
    pub fn new() -> Self {
        Self::default()
    }

    /// A snapshot of every message sent so far, oldest first.
    pub fn messages(&self) -> Vec<EmailMessage> {
        self.messages.lock().expect("mailer mutex poisoned").clone()
    }
}

#[async_trait]
impl Mailer for MemoryMailer {
    async fn send(&self, msg: EmailMessage) -> Result<(), MailError> {
        self.messages
            .lock()
            .expect("mailer mutex poisoned")
            .push(msg);
        Ok(())
    }
}

/// POSTs a generic JSON envelope `{"to","subject","html","text","type"}` to an
/// operator-configured webhook, with an optional `Authorization` header. This
/// is the production transport: point it at any HTTP endpoint (a serverless
/// function, an internal mail microservice, a provider's inbound webhook) that
/// forwards to a real mail provider.
pub struct HttpMailer {
    client: reqwest::Client,
    url: String,
    authorization: Option<Secret>,
}

impl HttpMailer {
    pub fn new(url: impl Into<String>, authorization: Option<Secret>) -> Self {
        // reqwest's `rustls-no-provider` feature requires a process-wide
        // crypto provider to be installed before the first HTTPS request;
        // this is a no-op if one is already installed (e.g. by iroh's own
        // networking stack in a replicated deployment).
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        Self {
            client: reqwest::Client::new(),
            url: url.into(),
            authorization,
        }
    }
}

#[async_trait]
impl Mailer for HttpMailer {
    async fn send(&self, msg: EmailMessage) -> Result<(), MailError> {
        let body = serde_json::json!({
            "to": msg.to,
            "subject": msg.subject,
            "html": msg.html,
            "text": msg.text,
            "type": msg.email_type.as_str(),
        });
        let bytes = serde_json::to_vec(&body)
            .map_err(|e| MailError::Send(format!("failed to encode mail webhook body: {e}")))?;

        let mut req = self
            .client
            .post(&self.url)
            .header("content-type", "application/json")
            .body(bytes);
        if let Some(auth) = &self.authorization {
            req = req.header("authorization", auth.expose());
        }

        let resp = req.send().await.map_err(|e| {
            MailError::Send(format!(
                "mail webhook request failed: {}",
                e.status()
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| "connection error".to_string())
            ))
        })?;

        if !resp.status().is_success() {
            return Err(MailError::Send(format!(
                "mail webhook returned {}",
                resp.status().as_u16()
            )));
        }
        Ok(())
    }
}

/// Writes the message to the trace log. Strictly opt-in (`--mailer-log`) —
/// this prints the verification URL (embedded in `html`/`text`), which is
/// otherwise treated as sensitive. Never used as an implicit fallback.
pub struct LogMailer;

#[async_trait]
impl Mailer for LogMailer {
    async fn send(&self, msg: EmailMessage) -> Result<(), MailError> {
        tracing::info!(
            to = %msg.to,
            subject = %msg.subject,
            email_type = msg.email_type.as_str(),
            body = %msg.text,
            "mailer (log transport): would send email"
        );
        Ok(())
    }
}

/// No transport configured. Every send fails typed — a flow that requires
/// email must never silently succeed without actually delivering anything.
pub struct UnconfiguredMailer;

#[async_trait]
impl Mailer for UnconfiguredMailer {
    async fn send(&self, _msg: EmailMessage) -> Result<(), MailError> {
        Err(MailError::NotConfigured)
    }

    fn is_configured(&self) -> bool {
        false
    }
}

/// A transport that is expressible in config but not implemented in this
/// slice (currently: SMTP).
pub struct UnsupportedMailer(pub &'static str);

#[async_trait]
impl Mailer for UnsupportedMailer {
    async fn send(&self, _msg: EmailMessage) -> Result<(), MailError> {
        Err(MailError::TransportUnsupported(self.0))
    }
}

/// Which [`Mailer`] transport [`build_mailer`] should construct.
#[derive(Debug, Clone, Default)]
pub enum MailerConfig {
    /// No transport. Email-dependent flows fail typed.
    #[default]
    Unconfigured,
    /// Writes to the trace log (see [`LogMailer`]). Opt-in only.
    Log,
    /// Generic JSON webhook (see [`HttpMailer`]).
    Http {
        url: String,
        authorization: Option<Secret>,
    },
    /// SMTP relay. Expressible, but not implemented in this slice — see
    /// [`UnsupportedMailer`].
    Smtp { host: String },
}

/// Constructs the [`Mailer`] a [`MailerConfig`] describes.
pub fn build_mailer(cfg: &MailerConfig) -> Arc<dyn Mailer> {
    match cfg {
        MailerConfig::Unconfigured => Arc::new(UnconfiguredMailer),
        MailerConfig::Log => Arc::new(LogMailer),
        MailerConfig::Http { url, authorization } => {
            Arc::new(HttpMailer::new(url.clone(), authorization.clone()))
        }
        MailerConfig::Smtp { host: _ } => Arc::new(UnsupportedMailer("smtp")),
    }
}

/// Substitutes `{{ .Var }}`-style placeholders (GoTrue's template variable
/// naming, so a future custom-template feature can reuse the same names) via
/// plain string replacement — no template engine.
pub fn render(template: &str, vars: &[(&str, &str)]) -> String {
    let mut out = template.to_string();
    for (name, value) in vars {
        out = out.replace(&format!("{{{{ .{name} }}}}"), value);
    }
    out
}

/// Built-in templates. `{{ .ConfirmationURL }}` is the link the recipient
/// clicks; `{{ .Token }}` / `{{ .SiteURL }}` / `{{ .Email }}` are available for
/// deployments that want to render their own link format.
pub const SIGNUP_SUBJECT: &str = "Confirm Your Signup";
pub const SIGNUP_TEMPLATE_TEXT: &str =
    "Confirm your signup by visiting the following link: {{ .ConfirmationURL }}";
pub const SIGNUP_TEMPLATE_HTML: &str =
    "<p>Confirm your signup by clicking <a href=\"{{ .ConfirmationURL }}\">this link</a>.</p>";

pub const RECOVERY_SUBJECT: &str = "Reset Your Password";
pub const RECOVERY_TEMPLATE_TEXT: &str =
    "Reset your password by visiting the following link: {{ .ConfirmationURL }}";
pub const RECOVERY_TEMPLATE_HTML: &str =
    "<p>Reset your password by clicking <a href=\"{{ .ConfirmationURL }}\">this link</a>.</p>";

pub const MAGICLINK_SUBJECT: &str = "Your Magic Link";
pub const MAGICLINK_TEMPLATE_TEXT: &str =
    "Sign in by visiting the following link: {{ .ConfirmationURL }}";
pub const MAGICLINK_TEMPLATE_HTML: &str =
    "<p>Sign in by clicking <a href=\"{{ .ConfirmationURL }}\">this link</a>.</p>";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_substitutes_all_vars() {
        let out = render(
            "hi {{ .Email }}, go to {{ .ConfirmationURL }}",
            &[("Email", "a@b.com"), ("ConfirmationURL", "https://x/y")],
        );
        assert_eq!(out, "hi a@b.com, go to https://x/y");
    }

    #[test]
    fn render_leaves_unknown_placeholders() {
        let out = render("{{ .Unknown }}", &[("Email", "a@b.com")]);
        assert_eq!(out, "{{ .Unknown }}");
    }

    #[tokio::test]
    async fn memory_mailer_captures_in_order() {
        let mailer = MemoryMailer::new();
        for i in 0..3 {
            mailer
                .send(EmailMessage {
                    to: format!("user{i}@x.com"),
                    subject: "s".into(),
                    html: "h".into(),
                    text: "t".into(),
                    email_type: EmailType::Signup,
                })
                .await
                .unwrap();
        }
        let msgs = mailer.messages();
        assert_eq!(msgs.len(), 3);
        assert_eq!(msgs[0].to, "user0@x.com");
        assert_eq!(msgs[2].to, "user2@x.com");
    }

    #[tokio::test]
    async fn unconfigured_mailer_is_not_configured_and_fails_send() {
        let mailer = UnconfiguredMailer;
        assert!(!mailer.is_configured());
        let err = mailer
            .send(EmailMessage {
                to: "a@b.com".into(),
                subject: "s".into(),
                html: "h".into(),
                text: "t".into(),
                email_type: EmailType::Recovery,
            })
            .await
            .unwrap_err();
        assert_eq!(err, MailError::NotConfigured);
    }

    #[tokio::test]
    async fn build_mailer_maps_smtp_to_unsupported() {
        let mailer = build_mailer(&MailerConfig::Smtp {
            host: "localhost".into(),
        });
        assert!(mailer.is_configured());
        let err = mailer
            .send(EmailMessage {
                to: "a@b.com".into(),
                subject: "s".into(),
                html: "h".into(),
                text: "t".into(),
                email_type: EmailType::MagicLink,
            })
            .await
            .unwrap_err();
        assert_eq!(err, MailError::TransportUnsupported("smtp"));
    }

    #[test]
    fn build_mailer_maps_unconfigured_default() {
        let mailer = build_mailer(&MailerConfig::default());
        assert!(!mailer.is_configured());
    }

    #[test]
    fn email_type_as_str() {
        assert_eq!(EmailType::Signup.as_str(), "signup");
        assert_eq!(EmailType::Recovery.as_str(), "recovery");
        assert_eq!(EmailType::MagicLink.as_str(), "magiclink");
    }
}
