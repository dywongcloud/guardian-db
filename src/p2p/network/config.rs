// Iroh client configuration.
//
// Centralizes all configuration options for the native Iroh client.
// Focuses on iroh-blobs (storage) and iroh-gossip (pubsub).
// Uses discovery via Pkarr/DNS/mDNS.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::Duration;

/// Relay-server override: controls how the endpoint falls back to a relayed
/// connection when a direct (hole-punched) QUIC path cannot be established.
///
/// `ClientConfig.relay = None` (the default) derives relay behavior from
/// `enable_discovery_n0`: n0.computer's production relay servers when
/// discovery is enabled, no relay at all when it is disabled - this preserves
/// existing behavior for every config profile below. Set this explicitly to
/// run against self-hosted relay infrastructure (or to force-enable/disable
/// relay) independently of the discovery setting - e.g. n0's DNS discovery
/// with a private relay fleet, or no discovery at all (static `known_peers`)
/// but still with NAT-traversal fallback via your own relay.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum RelayConfig {
    /// No relay fallback; only direct (hole-punched) connections are possible.
    Disabled,
    /// n0.computer's production relay servers.
    N0Default,
    /// n0.computer's staging relay servers.
    N0Staging,
    /// One or more self-hosted relay server URLs, e.g. `https://relay.example.com`.
    Custom(Vec<String>),
}

/// Complete configuration for the Iroh client.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientConfig {
    /// Enables PubSub functionality (iroh-gossip).
    pub enable_pubsub: bool,

    /// Path where Iroh data is stored (blobs + docs).
    pub data_store_path: Option<PathBuf>,

    /// Port for the Iroh endpoint (0 = random port).
    pub port: u16,

    /// Bootstrap peer addresses to register on the endpoint at startup, bypassing
    /// any discovery service. Each entry carries the peer's [`NodeId`] plus its
    /// reachable transport addresses, so peers can rendezvous purely from static
    /// configuration (no dependency on n0.computer's public discovery/relay
    /// infrastructure, mDNS, or a manual `add_node_addr` call after construction).
    pub known_peers: Vec<iroh::EndpointAddr>,

    /// Enables discovery via n0.computer (Pkarr + DNS).
    pub enable_discovery_n0: bool,

    /// Enables discovery via mDNS (local network).
    pub enable_discovery_mdns: bool,

    /// Explicit relay-server override. See [`RelayConfig`]. `None` derives
    /// relay behavior from `enable_discovery_n0` (existing behavior).
    #[serde(default)]
    pub relay: Option<RelayConfig>,

    /// Iroh networking settings.
    pub network: NetworkConfig,

    /// Storage settings (iroh-blobs).
    pub storage: StorageConfig,

    /// Gossip settings (iroh-gossip).
    pub gossip: GossipConfig,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            enable_pubsub: true,
            data_store_path: Some(PathBuf::from("./iroh_data")),
            port: 0, // Random port.
            known_peers: vec![],
            enable_discovery_n0: true,   // Discovery via Pkarr/DNS.
            enable_discovery_mdns: true, // Local discovery.
            relay: None,
            network: NetworkConfig::default(),
            storage: StorageConfig::default(),
            gossip: GossipConfig::default(),
        }
    }
}

impl ClientConfig {
    /// Creates a minimal configuration for development.
    pub fn development() -> Self {
        Self {
            enable_pubsub: true,
            data_store_path: Some("./tmp/iroh_dev".into()),
            port: 0, // Random port.
            known_peers: vec![],
            enable_discovery_n0: false,  // Disabled for local dev.
            enable_discovery_mdns: true, // Local discovery only.
            relay: None,
            network: NetworkConfig::development(),
            storage: StorageConfig::development(),
            gossip: GossipConfig::development(),
        }
    }

    /// Creates a configuration for production.
    pub fn production() -> Self {
        Self {
            enable_pubsub: true,
            data_store_path: Some("/var/lib/iroh".into()),
            port: 4001,                  // Fixed port for production.
            known_peers: vec![],         // Would be populated with peers.
            enable_discovery_n0: true,   // Global discovery via n0.computer.
            enable_discovery_mdns: true, // Local discovery as well.
            relay: None,
            network: NetworkConfig::production(),
            storage: StorageConfig::production(),
            gossip: GossipConfig::production(),
        }
    }

    /// Configuration for testing only.
    pub fn testing() -> Self {
        Self {
            enable_pubsub: true,
            data_store_path: None, // In-memory.
            port: 0,               // Random port.
            known_peers: vec![],
            enable_discovery_n0: false,
            enable_discovery_mdns: false,
            relay: None,
            network: NetworkConfig::testing(),
            storage: StorageConfig::testing(),
            gossip: GossipConfig::testing(),
        }
    }

    /// Enables offline mode (no networking).
    pub fn offline() -> Self {
        Self {
            enable_pubsub: false,
            enable_discovery_n0: false,
            enable_discovery_mdns: false,
            ..Self::development()
        }
    }

    /// Adds a known peer address for the initial connection, bypassing discovery.
    /// If the peer's `NodeId` is already present, its address is updated.
    pub fn add_known_peer(&mut self, peer: iroh::EndpointAddr) {
        if let Some(existing) = self.known_peers.iter_mut().find(|p| p.id == peer.id) {
            *existing = peer;
        } else {
            self.known_peers.push(peer);
        }
    }

    /// Sets the Iroh endpoint port.
    pub fn with_port(mut self, port: u16) -> Self {
        self.port = port;
        self
    }

    /// Sets the storage path.
    pub fn with_data_path<P: Into<PathBuf>>(mut self, path: P) -> Self {
        self.data_store_path = Some(path.into());
        self
    }

    /// Sets an explicit relay override, e.g. to point at self-hosted relay
    /// infrastructure instead of n0.computer's default relay servers.
    pub fn with_relay(mut self, relay: RelayConfig) -> Self {
        self.relay = Some(relay);
        self
    }

    /// Validates the configuration.
    pub fn validate(&self) -> Result<(), String> {
        // Check the consistency of the Iroh configuration.

        // Validate the port.
        // Port 0 is valid (random); ports < 1024 require privileges.
        if self.port > 0 && self.port < 1024 {
            return Err("Port < 1024 requires administrator privileges".to_string());
        }

        // Validate the storage path if provided.
        if let Some(path) = &self.data_store_path
            && path.as_os_str().is_empty()
        {
            return Err("Storage path cannot be empty".to_string());
        }

        // Validate the storage settings.
        if self.storage.max_cache_size == 0 {
            return Err("Cache size cannot be zero".to_string());
        }

        // Validate the relay override, if any.
        if let Some(RelayConfig::Custom(urls)) = &self.relay {
            if urls.is_empty() {
                return Err("RelayConfig::Custom requires at least one relay URL (use \
                     RelayConfig::Disabled for no relay)"
                    .to_string());
            }
            for url in urls {
                if let Err(e) = url.parse::<iroh::RelayUrl>() {
                    return Err(format!("Invalid custom relay URL '{url}': {e}"));
                }
            }
        }

        Ok(())
    }

    /// Returns whether persistent storage is used (vs. in-memory).
    pub fn uses_persistent_storage(&self) -> bool {
        self.data_store_path.is_some()
    }

    /// Returns whether any discovery method is enabled.
    pub fn has_discovery_enabled(&self) -> bool {
        self.enable_discovery_n0 || self.enable_discovery_mdns
    }
}

/// Iroh-specific networking settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    /// Timeout for endpoint connections.
    pub connection_timeout: Duration,

    /// Maximum number of simultaneous peers.
    pub max_peers_per_session: usize,

    /// Network I/O buffer size (bytes).
    pub io_buffer_size: usize,

    /// Keep-alive interval for connections.
    pub keepalive_interval: Duration,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            connection_timeout: Duration::from_secs(30),
            max_peers_per_session: 100,
            io_buffer_size: 64 * 1024, // 64KB
            keepalive_interval: Duration::from_secs(60),
        }
    }
}

impl NetworkConfig {
    pub fn development() -> Self {
        Self {
            connection_timeout: Duration::from_secs(10),
            max_peers_per_session: 10,
            io_buffer_size: 16 * 1024, // 16 KB
            keepalive_interval: Duration::from_secs(30),
        }
    }

    pub fn production() -> Self {
        Self {
            connection_timeout: Duration::from_secs(60),
            max_peers_per_session: 1000,
            io_buffer_size: 128 * 1024, // 128 KB
            keepalive_interval: Duration::from_secs(120),
        }
    }

    pub fn testing() -> Self {
        Self {
            connection_timeout: Duration::from_secs(5),
            max_peers_per_session: 5,
            io_buffer_size: 8 * 1024, // 8KB
            keepalive_interval: Duration::from_secs(15),
        }
    }
}

/// Storage settings (iroh-blobs).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfig {
    /// Enables an in-memory cache for blobs.
    pub enable_memory_cache: bool,

    /// Maximum in-memory cache size (bytes).
    pub max_cache_size: usize,

    /// Maximum size of an individual blob (bytes).
    pub max_blob_size: usize,

    /// Enables automatic garbage collection.
    pub enable_gc: bool,

    /// Garbage collection interval.
    pub gc_interval: Duration,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            enable_memory_cache: true,
            max_cache_size: 100 * 1024 * 1024, // 100 MB
            max_blob_size: 10 * 1024 * 1024,   // 10 MB per blob
            enable_gc: true,
            gc_interval: Duration::from_secs(3600), // 1 hour
        }
    }
}

impl StorageConfig {
    pub fn development() -> Self {
        Self {
            enable_memory_cache: true,
            max_cache_size: 10 * 1024 * 1024, // 10 MB
            max_blob_size: 5 * 1024 * 1024,   // 5 MB per blob
            enable_gc: false,                 // Disabled for debugging.
            gc_interval: Duration::from_secs(3600),
        }
    }

    pub fn production() -> Self {
        Self {
            enable_memory_cache: true,
            max_cache_size: 1024 * 1024 * 1024, // 1 GB
            max_blob_size: 100 * 1024 * 1024,   // 100 MB per blob
            enable_gc: true,
            gc_interval: Duration::from_secs(1800), // 30 minutes
        }
    }

    pub fn testing() -> Self {
        Self {
            enable_memory_cache: false,
            max_cache_size: 1024 * 1024, // 1 MB
            max_blob_size: 512 * 1024,   // 512 KB per blob
            enable_gc: false,
            gc_interval: Duration::from_secs(3600),
        }
    }
}

/// Gossip settings (iroh-gossip).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GossipConfig {
    /// Maximum gossip message size (bytes).
    pub max_message_size: usize,

    /// Buffer size for message streams.
    pub message_buffer_size: usize,

    /// Timeout for gossip operations.
    pub operation_timeout: Duration,

    /// Heartbeat interval of the gossip protocol.
    pub heartbeat_interval: Duration,

    /// Maximum number of simultaneous topics.
    pub max_topics: usize,
}

impl Default for GossipConfig {
    fn default() -> Self {
        Self {
            max_message_size: 1024 * 1024, // 1MB
            message_buffer_size: 1000,
            operation_timeout: Duration::from_secs(30),
            heartbeat_interval: Duration::from_secs(1),
            max_topics: 100,
        }
    }
}

impl GossipConfig {
    pub fn development() -> Self {
        Self {
            max_message_size: 64 * 1024, // 64KB
            message_buffer_size: 100,
            operation_timeout: Duration::from_secs(10),
            heartbeat_interval: Duration::from_secs(2),
            max_topics: 10,
        }
    }

    pub fn production() -> Self {
        Self {
            max_message_size: 10 * 1024 * 1024, // 10MB
            message_buffer_size: 10000,
            operation_timeout: Duration::from_secs(60),
            heartbeat_interval: Duration::from_millis(500),
            max_topics: 1000,
        }
    }

    pub fn testing() -> Self {
        Self {
            max_message_size: 1024 * 1024, // 1 MB - must support multiple serialized entries
            message_buffer_size: 10,
            operation_timeout: Duration::from_secs(5),
            heartbeat_interval: Duration::from_secs(5),
            max_topics: 5,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = ClientConfig::default();
        assert!(config.enable_pubsub);
        assert!(config.enable_discovery_n0);
        assert!(config.enable_discovery_mdns);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_development_config() {
        let config = ClientConfig::development();
        assert!(config.enable_pubsub);
        assert!(!config.enable_discovery_n0); // Disabled for dev.
        assert!(config.enable_discovery_mdns);
        assert_eq!(config.port, 0); // Random port.
    }

    #[test]
    fn test_production_config() {
        let config = ClientConfig::production();
        assert!(config.enable_pubsub);
        assert!(config.enable_discovery_n0);
        assert!(config.enable_discovery_mdns);
        assert_eq!(config.port, 4001); // Fixed port.
    }

    #[test]
    fn test_testing_config() {
        let config = ClientConfig::testing();
        assert!(config.enable_pubsub);
        assert!(!config.enable_discovery_n0);
        assert!(!config.enable_discovery_mdns);
        assert_eq!(config.port, 0);
    }

    #[test]
    fn test_offline_config() {
        let config = ClientConfig::offline();
        assert!(!config.enable_pubsub);
        assert!(!config.enable_discovery_n0);
        assert!(!config.enable_discovery_mdns);
    }

    #[test]
    fn test_config_validation() {
        let mut config = ClientConfig::default();

        // Valid configuration.
        assert!(config.validate().is_ok());

        // Privileged port (< 1024) that is not 0.
        config.port = 80;
        assert!(config.validate().is_err());

        // Port 0 (random) is valid.
        config.port = 0;
        assert!(config.validate().is_ok());

        // A normal port is valid.
        config.port = 4001;
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_add_known_peer() {
        use iroh::{EndpointAddr, SecretKey};

        let mut config = ClientConfig::default();
        let secret = SecretKey::generate();
        let peer_id = secret.public();
        let peer = EndpointAddr::new(peer_id);

        config.add_known_peer(peer.clone());
        assert!(config.known_peers.iter().any(|p| p.id == peer_id));

        // Should not duplicate; re-adding the same NodeId updates in place.
        config.add_known_peer(peer);
        assert_eq!(config.known_peers.len(), 1);
    }

    #[test]
    fn test_with_data_path() {
        let config = ClientConfig::default().with_data_path("/custom/path");
        assert_eq!(config.data_store_path, Some(PathBuf::from("/custom/path")));
    }

    #[test]
    fn test_relay_defaults_to_none() {
        // Every profile derives relay behavior from enable_discovery_n0 unless
        // explicitly overridden.
        assert_eq!(ClientConfig::default().relay, None);
        assert_eq!(ClientConfig::development().relay, None);
        assert_eq!(ClientConfig::production().relay, None);
        assert_eq!(ClientConfig::testing().relay, None);
        assert_eq!(ClientConfig::offline().relay, None);
    }

    #[test]
    fn test_with_relay() {
        let config = ClientConfig::default().with_relay(RelayConfig::Disabled);
        assert_eq!(config.relay, Some(RelayConfig::Disabled));

        let config = ClientConfig::default().with_relay(RelayConfig::Custom(vec![
            "https://relay.example.com".to_string(),
        ]));
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_relay_custom_rejects_empty_list() {
        let config = ClientConfig::default().with_relay(RelayConfig::Custom(vec![]));
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_relay_custom_rejects_invalid_url() {
        let config =
            ClientConfig::default().with_relay(RelayConfig::Custom(vec!["not a url".to_string()]));
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_relay_custom_accepts_valid_urls() {
        let config = ClientConfig::default().with_relay(RelayConfig::Custom(vec![
            "https://relay1.example.com".to_string(),
            "https://relay2.example.com".to_string(),
        ]));
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_relay_disabled_and_n0_default_and_staging_are_valid() {
        for relay in [
            RelayConfig::Disabled,
            RelayConfig::N0Default,
            RelayConfig::N0Staging,
        ] {
            let config = ClientConfig::default().with_relay(relay);
            assert!(config.validate().is_ok());
        }
    }

    #[test]
    fn test_with_port() {
        let config = ClientConfig::default().with_port(8080);
        assert_eq!(config.port, 8080);
    }

    #[test]
    fn test_persistent_storage_detection() {
        // With persistent storage.
        let persistent_config = ClientConfig::development();
        assert!(persistent_config.uses_persistent_storage());

        // In-memory.
        let memory_config = ClientConfig::testing();
        assert!(!memory_config.uses_persistent_storage());
    }

    #[test]
    fn test_discovery_detection() {
        // With discovery enabled.
        let with_discovery = ClientConfig::default();
        assert!(with_discovery.has_discovery_enabled());

        // Without discovery.
        let without_discovery = ClientConfig::offline();
        assert!(!without_discovery.has_discovery_enabled());
    }
}
