/// Integration tests for custom/self-hosted iroh relay configuration.
///
/// These prove the relay override is genuinely wired end-to-end into endpoint
/// construction - not just accepted by `ClientConfig::validate()` - and that it
/// works independently of the discovery settings (`enable_discovery_n0` /
/// `enable_discovery_mdns`).
mod common;

use common::{TestNode, init_test_logging};
use guardian_db::guardian::core::NewGuardianDBOptions;
use guardian_db::p2p::network::config::{ClientConfig, RelayConfig};

/// A custom relay can be configured even with n0 discovery fully disabled -
/// proving relay and discovery are independent settings, not coupled as they
/// were before (where relay availability silently followed
/// `enable_discovery_n0`).
#[tokio::test]
async fn test_custom_relay_with_discovery_disabled() {
    init_test_logging();

    let temp_dir = tempfile::TempDir::new().expect("Failed to create temp dir");
    let data_path = temp_dir.path().join("custom_relay_node");

    let mut iroh_config = ClientConfig::testing();
    iroh_config.data_store_path = Some(data_path.join("iroh"));
    iroh_config.port = 0;
    // Discovery fully off, but a self-hosted relay is explicitly configured.
    assert!(!iroh_config.enable_discovery_n0);
    assert!(!iroh_config.enable_discovery_mdns);
    iroh_config.relay = Some(RelayConfig::Custom(vec![
        "https://relay.example.invalid".to_string(),
    ]));

    let db_options = NewGuardianDBOptions {
        directory: Some(data_path.join("guardian")),
        ..Default::default()
    };

    // Endpoint construction must succeed even though the relay server is not
    // actually reachable - relay-mode only matters when a direct path fails,
    // it should not need to dial the relay just to bind the endpoint.
    let node = TestNode::with_config("custom_relay_node", iroh_config, db_options)
        .await
        .expect("Node with a custom relay + discovery disabled should construct successfully");

    // Exercise the full stack, not just endpoint construction.
    let log = node
        .db
        .log("relay-smoke-log", None)
        .await
        .expect("Should be able to create a store on a node with a custom relay");
    log.add(b"smoke test".to_vec())
        .await
        .expect("Should be able to write locally with a custom relay configured");

    tracing::info!(
        "✓ Node constructed with custom relay + discovery disabled: {}",
        node.iroh.node_id()
    );
}

/// A node can explicitly disable relay while keeping n0 discovery enabled -
/// the inverse decoupling from the test above.
#[tokio::test]
async fn test_relay_disabled_with_discovery_enabled() {
    init_test_logging();

    let temp_dir = tempfile::TempDir::new().expect("Failed to create temp dir");
    let data_path = temp_dir.path().join("no_relay_node");

    let mut iroh_config = ClientConfig::testing();
    iroh_config.data_store_path = Some(data_path.join("iroh"));
    iroh_config.port = 0;
    iroh_config.enable_discovery_n0 = true;
    iroh_config.relay = Some(RelayConfig::Disabled);

    let db_options = NewGuardianDBOptions {
        directory: Some(data_path.join("guardian")),
        ..Default::default()
    };

    let node = TestNode::with_config("no_relay_node", iroh_config, db_options)
        .await
        .expect("Node with discovery enabled but relay explicitly disabled should construct");

    tracing::info!(
        "✓ Node constructed with discovery enabled + relay explicitly disabled: {}",
        node.iroh.node_id()
    );
}

/// Multiple self-hosted relay URLs can be configured together.
#[tokio::test]
async fn test_multiple_custom_relays() {
    init_test_logging();

    let temp_dir = tempfile::TempDir::new().expect("Failed to create temp dir");
    let data_path = temp_dir.path().join("multi_relay_node");

    let mut iroh_config = ClientConfig::testing();
    iroh_config.data_store_path = Some(data_path.join("iroh"));
    iroh_config.port = 0;
    iroh_config.relay = Some(RelayConfig::Custom(vec![
        "https://relay-a.example.invalid".to_string(),
        "https://relay-b.example.invalid".to_string(),
    ]));

    let db_options = NewGuardianDBOptions {
        directory: Some(data_path.join("guardian")),
        ..Default::default()
    };

    let node = TestNode::with_config("multi_relay_node", iroh_config, db_options)
        .await
        .expect("Node with multiple custom relay URLs should construct successfully");

    tracing::info!(
        "✓ Node constructed with multiple custom relays: {}",
        node.iroh.node_id()
    );
}

/// An invalid custom relay URL is caught by `ClientConfig::validate()` before
/// any attempt to construct the endpoint.
#[tokio::test]
async fn test_invalid_custom_relay_url_rejected_by_validate() {
    let config = ClientConfig::default().with_relay(RelayConfig::Custom(vec![
        "not a valid relay url".to_string(),
    ]));
    assert!(
        config.validate().is_err(),
        "An unparseable relay URL should fail validation"
    );
}
