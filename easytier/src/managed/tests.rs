use super::*;
use crate::instance::factory::native_instance_manager;
use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};

fn options(dir: &Path) -> ManagedOptions {
    ManagedOptions {
        state_dir: dir.join("managed"),
        origin: DEFAULT_ORIGIN.to_owned(),
        import_config: None,
        relay: None,
        relay_invitation_file: None,
    }
}
fn fixture_client(options: ManagedOptions) -> Client {
    let identity = load_identity(&options).unwrap();
    Client {
        url: origin(&options.origin).unwrap(),
        http: reqwest::Client::new(),
        identity,
        options,
        watermark: Watermark::default(),
        authority: None,
        manager: Arc::new(native_instance_manager()),
        active: Arc::new(Mutex::new(None)),
        lifecycle: Arc::new(Mutex::new(())),
        stable_config: None,
        peer_urls: Default::default(),
        telemetry_credit: 8192,
        telemetry_last: Instant::now(),
        telemetry_last_fingerprint: None,
        telemetry_sequence: 0,
        telemetry_boot: None,
        telemetry_rate: 16384,
        telemetry_pending: None,
        telemetry_expired_batches: 0,
        telemetry_failed_attempts: 0,
        telemetry_round: 0,
    }
}
fn signed(key: &SigningKey, value: &Value) -> Vec<u8> {
    let raw = serde_json::to_vec(value).unwrap();
    let mut message = RESPONSE_DOMAIN.to_vec();
    message.extend_from_slice(&raw);
    serde_json::to_vec(&Envelope {
        payload: URL_SAFE_NO_PAD.encode(raw),
        signature: URL_SAFE_NO_PAD.encode(key.sign(&message).to_bytes()),
        key_id: Some("test-authority".into()),
        algorithm: Some("Ed25519".into()),
    })
    .unwrap()
}
fn authority(key: &SigningKey, origin: String) -> Authority {
    Authority {
        version: 1,
        origin,
        network_id: "test-managed".into(),
        key_id: "test-authority".into(),
        public_key: STANDARD.encode(key.verifying_key().as_bytes()),
    }
}
#[test]
fn private_identity_import_preserves_overlay_not_control_key() {
    let dir = tempfile::tempdir().unwrap();
    let mut opts = options(dir.path());
    let id = Uuid::new_v4();
    let overlay = STANDARD.encode([47u8; 32]);
    let import = dir.path().join("old.toml");
    std::fs::write(&import,format!("instance_id = '{id}'\n[network_identity]\nnetwork_name = 'test-managed'\nnetwork_secret = 'old-root-secret'\n[secure_mode]\nenabled = true\nlocal_private_key = '{overlay}'\n")).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&import, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    opts.import_config = Some(import);
    let identity = load_identity(&opts).unwrap();
    assert_eq!(identity.instance_id, id);
    assert_eq!(identity.overlay_private_key, overlay);
    assert!(identity.backbone);
    assert_ne!(identity.control_private_key, overlay);
    let again = load_identity(&opts).unwrap();
    assert_eq!(identity.control_private_key, again.control_private_key);
    let public = status(&opts).unwrap();
    let text = serde_json::to_string(&public).unwrap();
    assert!(!text.contains(&overlay));
    assert!(!text.contains(&identity.control_private_key));
    assert_eq!(public["role"], "backbone");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(opts.state_dir.join("identity.json"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
}
#[test]
fn management_origin_and_state_fail_closed() {
    assert!(origin("http://localhost").is_err());
    assert!(origin("https://user:pass@example.com").is_err());
    assert!(origin("https://example.com/path").is_err());
    let dir = tempfile::tempdir().unwrap();
    let opts = options(dir.path());
    prepare_dir(&opts.state_dir).unwrap();
    let held = lock_state(&opts.state_dir).unwrap();
    assert!(lock_state(&opts.state_dir).is_err());
    drop(held);
    assert!(lock_state(&opts.state_dir).is_ok());
}
#[test]
fn response_signature_device_expiry_and_generation_are_bound() {
    let dir = tempfile::tempdir().unwrap();
    let mut client = fixture_client(options(dir.path()));
    let key = SigningKey::from_bytes(&[9u8; 32]);
    client.authority = Some(authority(&key, client.url.to_string()));
    client.watermark.auth_revision = 4;
    client.watermark.session_generation = 10;
    let request = Uuid::new_v4();
    let time = now().unwrap();
    let valid = json!({"version":1,"operation":"sync","request_id":request,"device_id":client.identity.device_id,
        "state":"approved","role":"leaf","network_id":"test-managed","auth_revision":4,"session_generation":11,"issued_at":time,"expires_at":time+120,"lease_id":"test-lease"});
    assert!(
        client
            .verify_reply(&signed(&key, &valid), "sync", request, 11)
            .is_ok()
    );
    for (field, bad) in [
        ("device_id", json!(Uuid::new_v4())),
        ("request_id", json!(Uuid::new_v4())),
        ("session_generation", json!(10)),
        ("auth_revision", json!(3)),
        ("expires_at", json!(time - 1)),
        ("expires_at", json!(time + 301)),
    ] {
        let mut changed = valid.clone();
        changed[field] = bad;
        assert!(
            client
                .verify_reply(&signed(&key, &changed), "sync", request, 11)
                .is_err(),
            "accepted invalid {field}"
        );
    }
    assert!(
        client
            .verify_reply(
                &signed(&SigningKey::from_bytes(&[8u8; 32]), &valid),
                "sync",
                request,
                11
            )
            .is_err()
    );
    let mut old = valid;
    old["operation"] = json!("challenge");
    old["session_generation"] = json!(10);
    assert!(
        client
            .verify_reply(&signed(&key, &old), "challenge", request, 0)
            .is_err()
    );
}

// Actual HTTPS transport + signed registration/challenge/sync + native instance lifecycle.
// This test authority is in-process and scoped to loopback; it is not a replacement
// implementation of the production management server.
#[cfg(feature = "websocket")]
struct TestAuthority {
    origin: String,
    http: reqwest::Client,
    state: Arc<AtomicU8>,
    syncs: Arc<AtomicUsize>,
    advertisements: Arc<AtomicUsize>,
    task: JoinHandle<()>,
}
#[cfg(feature = "websocket")]
impl Drop for TestAuthority {
    fn drop(&mut self) {
        self.task.abort();
    }
}
#[cfg(feature = "websocket")]
impl TestAuthority {
    async fn start(lease_seconds: i64) -> Self {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let cert_der = cert.cert.der().clone();
        let ca = reqwest::Certificate::from_der(cert_der.as_ref()).unwrap();
        let tls = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert_der],
            rustls::pki_types::PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()).into(),
        )
        .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let origin = format!("https://localhost:{port}/");
        let http = reqwest::Client::builder()
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
            .add_root_certificate(ca)
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap();
        let state = Arc::new(AtomicU8::new(0));
        let syncs = Arc::new(AtomicUsize::new(0));
        let s = state.clone();
        let count = syncs.clone();
        let advertisements = Arc::new(AtomicUsize::new(0));
        let adverts = advertisements.clone();
        let task = tokio::spawn(async move {
            let signer = SigningKey::from_bytes(&[9u8; 32]);
            let mut device_key = None;
            let mut overlay_key = String::new();
            let mut generation = 0u64;
            loop {
                let Ok((socket, _)) = listener.accept().await else {
                    break;
                };
                let Ok(mut stream) = acceptor.accept(socket).await else {
                    continue;
                };
                let mut data = Vec::new();
                let (header_len, body_len) = loop {
                    let mut buf = [0u8; 4096];
                    let n = stream.read(&mut buf).await.unwrap();
                    if n == 0 {
                        panic!("request closed before headers")
                    };
                    data.extend_from_slice(&buf[..n]);
                    assert!(data.len() < MAX_RESPONSE);
                    if let Some(end) = data.windows(4).position(|v| v == b"\r\n\r\n") {
                        let headers = String::from_utf8_lossy(&data[..end]);
                        let length = headers
                            .lines()
                            .find_map(|l| {
                                l.to_ascii_lowercase()
                                    .strip_prefix("content-length:")
                                    .map(|s| s.trim().parse::<usize>().unwrap())
                            })
                            .unwrap_or(0);
                        break (end + 4, length);
                    }
                };
                while data.len() < header_len + body_len {
                    let mut buf = [0u8; 4096];
                    let n = stream.read(&mut buf).await.unwrap();
                    assert_ne!(n, 0);
                    data.extend_from_slice(&buf[..n]);
                }
                let path = String::from_utf8_lossy(&data[..header_len])
                    .split_whitespace()
                    .nth(1)
                    .unwrap()
                    .to_owned();
                let body = if path == "/api/easytier/info" {
                    serde_json::to_vec(&json!({"version":1,"network_id":"test-managed","key_id":"test-authority","algorithm":"Ed25519","public_key":STANDARD.encode(signer.verifying_key().as_bytes())})).unwrap()
                } else {
                    let envelope: Envelope =
                        serde_json::from_slice(&data[header_len..header_len + body_len]).unwrap();
                    let raw = URL_SAFE_NO_PAD.decode(envelope.payload).unwrap();
                    let request: Value = serde_json::from_slice(&raw).unwrap();
                    let operation = request["operation"].as_str().unwrap();
                    if request["body"].get("relay").is_some() {
                        adverts.fetch_add(1, Ordering::SeqCst);
                    }
                    if operation == "enroll" {
                        let key = decode32(request["body"]["device_public_key"].as_str().unwrap())
                            .unwrap();
                        assert!(device_key.is_none_or(|old| old == key));
                        device_key = Some(key);
                        overlay_key = request["body"]["overlay_public_key"]
                            .as_str()
                            .unwrap()
                            .into();
                    }
                    let mut message = REQUEST_DOMAIN.to_vec();
                    message.extend_from_slice(&raw);
                    VerifyingKey::from_bytes(&device_key.unwrap())
                        .unwrap()
                        .verify_strict(
                            &message,
                            &Signature::from_slice(
                                &URL_SAFE_NO_PAD.decode(envelope.signature).unwrap(),
                            )
                            .unwrap(),
                        )
                        .unwrap();
                    let time = now().unwrap();
                    let mode = s.load(Ordering::SeqCst);
                    let state = match mode {
                        0 => "pending",
                        1 | 4 => "approved",
                        _ => "revoked",
                    };
                    if operation == "challenge" {
                        generation += 1;
                    }
                    if operation == "sync" {
                        assert_eq!(request["session_generation"], generation);
                        assert_eq!(request["challenge"], "0123456789abcdef0123456789abcdef");
                        count.fetch_add(1, Ordering::SeqCst);
                    }
                    let mut reply = json!({"version":1,"operation":operation,"request_id":request["request_id"],"device_id":request["device_id"],"state":state,"role":"leaf","network_id":"test-managed","auth_revision":if mode==0 {1}else if mode==2 {3}else {2},"session_generation":if operation=="enroll" {0}else{generation},"issued_at":time,"expires_at":time+lease_seconds,"lease_id":"fixture-lease","config_revision":1,"config_toml":null,"directory":[],"telemetry_accepted":operation=="sync" && mode!=4});
                    let relay = request["body"].get("relay");
                    if relay.is_some() {
                        reply["role"] = json!("relay");
                    }
                    if operation == "challenge" {
                        reply["challenge"] = json!("0123456789abcdef0123456789abcdef");
                        reply["challenge_expires_at"] = json!(time + 30);
                    }
                    if state == "approved" && operation == "sync" {
                        reply["directory"] = json!([{"device_id":request["device_id"],"hostname":"fixture","overlay_ip":"10.253.254.1","overlay_public_key":overlay_key}]);
                        reply["config_toml"] = json!(
                            "ipv4 = '10.253.254.1/24'\nlisteners = []\n[network_identity]\nnetwork_name = 'test-managed'\n[flags]\nno_tun = true\nuse_smoltcp = true\nenable_ipv6 = false\ndisable_p2p = true\ndisable_upnp = true\ndisable_relay_data = true\n[secure_mode]\nenabled = true\n"
                        );
                    }
                    if state == "approved" && operation == "sync" && relay.is_some() {
                        let mut config: toml::Value =
                            toml::from_str(reply["config_toml"].as_str().unwrap()).unwrap();
                        config["listeners"] =
                            toml::Value::try_from(relay.unwrap()["listeners"].clone()).unwrap();
                        config["flags"]["disable_relay_data"] = toml::Value::Boolean(false);
                        reply["config_toml"] = json!(toml::to_string(&config).unwrap());
                    }
                    if mode == 4 && operation == "sync" {
                        signed(&SigningKey::from_bytes(&[18u8; 32]), &reply)
                    } else {
                        signed(&signer, &reply)
                    }
                };
                stream.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",body.len()).as_bytes()).await.unwrap();
                stream.write_all(&body).await.unwrap();
                stream.shutdown().await.unwrap();
            }
        });
        Self {
            origin,
            http,
            state,
            syncs,
            advertisements,
            task,
        }
    }
}
#[cfg(all(feature = "websocket", feature = "smoltcp"))]
#[tokio::test]
async fn https_enrollment_approval_native_instance_renewal_and_revocation() {
    let server = TestAuthority::start(120).await;
    let dir = tempfile::tempdir().unwrap();
    let mut opts = options(dir.path());
    opts.origin = server.origin.clone();
    let mut client = fixture_client(opts);
    client.http = server.http.clone();
    client.cycle().await.unwrap();
    assert!(
        client
            .manager
            .instance(client.identity.instance_id)
            .is_none()
    );
    server.state.store(1, Ordering::SeqCst);
    client.cycle().await.unwrap();
    let first = client
        .manager
        .instance(client.identity.instance_id)
        .unwrap();
    client.cycle().await.unwrap();
    assert!(
        Arc::ptr_eq(
            &first,
            &client
                .manager
                .instance(client.identity.instance_id)
                .unwrap()
        ),
        "unchanged network must hot-apply, not restart"
    );
    server.state.store(2, Ordering::SeqCst);
    client.cycle().await.unwrap();
    assert!(
        client
            .manager
            .instance(client.identity.instance_id)
            .is_none()
    );
    assert!(server.syncs.load(Ordering::SeqCst) >= 3);
}
#[cfg(all(feature = "websocket", feature = "smoltcp"))]
#[tokio::test]
async fn native_watchdog_expires_without_authority_contact() {
    let server = TestAuthority::start(2).await;
    server.state.store(1, Ordering::SeqCst);
    let dir = tempfile::tempdir().unwrap();
    let mut opts = options(dir.path());
    opts.origin = server.origin.clone();
    let id = status(&opts).unwrap()["instance_id"]
        .as_str()
        .unwrap()
        .parse::<Uuid>()
        .unwrap();
    let manager = Arc::new(native_instance_manager());
    let runtime =
        ManagedRuntime::start_with_http(opts.clone(), manager.clone(), server.http.clone())
            .unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        while manager.instance(id).is_none() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    drop(server);
    tokio::time::timeout(Duration::from_secs(5), async {
        while manager.instance(id).is_some() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    let state: Value =
        serde_json::from_slice(&std::fs::read(opts.state_dir.join("status.json")).unwrap())
            .unwrap();
    assert_eq!(state["state"], "expired");
    runtime.shutdown().await.unwrap();
}

#[tokio::test]
async fn invalid_managed_toml_does_not_expose_private_source_spans() {
    let dir = tempfile::tempdir().unwrap();
    let mut client = fixture_client(options(dir.path()));
    let sentinel = "PRIVATE_CONFIG_SENTINEL_DO_NOT_LOG";
    let time = now().unwrap();
    let reply:Reply=serde_json::from_value(json!({"version":1,"operation":"sync","request_id":Uuid::new_v4(),"device_id":client.identity.device_id,"state":"approved","role":"leaf","network_id":"test-managed","auth_revision":1,"session_generation":1,"issued_at":time,"expires_at":time+120,"lease_id":"test","config_toml":format!("root_secret = '{sentinel}'\n[bad table"),"directory":[{"device_id":client.identity.device_id,"hostname":"fixture","overlay_ip":"10.253.254.1","overlay_public_key":client.identity.overlay_public().unwrap()}]})).unwrap();
    let error = client.apply(reply).await.unwrap_err();
    assert!(!format!("{error:#}").contains(sentinel));
    assert_eq!(error.to_string(), "invalid managed TOML configuration");
}

#[cfg(all(feature = "websocket", feature = "smoltcp"))]
#[tokio::test]
async fn telemetry_cursor_commits_only_after_signed_authority_ack() {
    let server = TestAuthority::start(120).await;
    server.state.store(1, Ordering::SeqCst);
    let dir = tempfile::tempdir().unwrap();
    let mut opts = options(dir.path());
    opts.origin = server.origin.clone();
    let mut client = fixture_client(opts);
    client.http = server.http.clone();
    client.cycle().await.unwrap();
    let time = now().unwrap();
    let old_sequence = client.telemetry_sequence;
    let report = json!({"measured_at":time,"expires_at":time+120,"flows":[],"links":[],"routes":[],"coverage":{"state":"ack-test"}});
    client.telemetry_pending = Some(PendingTelemetry {
        report: report.clone(),
        sequence: 42,
        fingerprint: "ack-test".into(),
        expires_at: time + 120,
    });
    server.state.store(4, Ordering::SeqCst);
    assert!(client.cycle().await.is_err());
    assert_eq!(client.telemetry_sequence, old_sequence);
    assert_eq!(client.telemetry_pending.as_ref().unwrap().report, report);
    server.state.store(1, Ordering::SeqCst);
    client.cycle().await.unwrap();
    assert_eq!(client.telemetry_sequence, 42);
    assert!(client.telemetry_pending.is_none());
    client.stop("test_finished").await.unwrap();
}

#[tokio::test]
async fn pinned_authority_without_watermark_is_not_silently_reset() {
    let dir = tempfile::tempdir().unwrap();
    let opts = options(dir.path());
    let identity = load_identity(&opts).unwrap();
    persist(
        &opts.state_dir.join("authority.json"),
        &authority(&SigningKey::from_bytes(&[9; 32]), opts.origin.clone()),
    )
    .unwrap();
    let manager = Arc::new(native_instance_manager());
    assert!(ManagedRuntime::start(opts.clone(), manager).is_err());
    assert_eq!(
        load_identity(&opts).unwrap().control_private_key,
        identity.control_private_key
    );
    assert!(!opts.state_dir.join("watermark.json").exists());
}
#[test]
fn concurrent_first_status_cannot_replace_an_existing_identity() {
    let dir = tempfile::tempdir().unwrap();
    let opts = options(dir.path());
    prepare_dir(&opts.state_dir).unwrap();
    let held = lock_named(&opts.state_dir, "identity.lock").unwrap();
    assert!(status(&opts).is_err());
    drop(held);
    let first = status(&opts).unwrap();
    let second = status(&opts).unwrap();
    assert_eq!(first, second);
}

#[tokio::test]
async fn established_watermark_cannot_repin_missing_authority() {
    let dir = tempfile::tempdir().unwrap();
    let opts = options(dir.path());
    load_identity(&opts).unwrap();
    persist(
        &opts.state_dir.join("watermark.json"),
        &Watermark {
            auth_revision: 3,
            session_generation: 4,
        },
    )
    .unwrap();
    assert!(ManagedRuntime::start(opts.clone(), Arc::new(native_instance_manager())).is_err());
    assert!(!opts.state_dir.join("authority.json").exists());
}

#[test]
fn relay_intent_is_explicit_and_public_metadata_is_bounded() {
    let dir = tempfile::tempdir().unwrap();
    let mut opts = options(dir.path());
    let client = fixture_client(opts.clone());
    assert!(client.relay_body().unwrap().is_none());
    assert_eq!(client.identity.public().unwrap()["role"], "leaf");
    let relay = RelayAdvertisement {
        listeners: vec!["tcp://0.0.0.0:57220".into()],
        public_peers: vec!["tcp://8.8.8.8:57220".into()],
        region: "test-global".into(),
    };
    relay.validate().unwrap();
    for peer in [
        "tcp://127.0.0.1:57220",
        "tcp://10.0.0.1:57220",
        "tcp://example.com:57220",
        "tcp://user:pass@8.8.8.8:57220",
        "tcp://8.8.8.8:57220?token=secret",
        "tcp://8.8.8.8:57220/",
    ] {
        let mut bad = relay.clone();
        bad.public_peers = vec![peer.into()];
        assert!(
            bad.validate().is_err(),
            "accepted invalid relay endpoint {peer}"
        );
    }
    let mut bad_listener = relay.clone();
    bad_listener.listeners = vec!["tcp://10.0.0.2:57220".into()];
    assert!(bad_listener.validate().is_err());
    let mut websocket = relay.clone();
    websocket.public_peers = vec!["ws://8.8.8.8:80".into()];
    assert!(websocket.validate().is_err()); // no matching protocol/port listener
    websocket.listeners = vec!["ws://0.0.0.0:80".into()];
    websocket.validate().unwrap(); // explicit default port remains canonical
    websocket.public_peers = vec!["ws://8.8.8.8".into()];
    assert!(websocket.validate().is_err());
    opts.relay = Some(relay);
    let identity = load_identity(&opts).unwrap();
    assert!(identity.relay);
    assert!(!identity.backbone);
    // Merely dropping command-line role flags cannot silently erase persisted intent.
    assert_eq!(status(&options(dir.path())).unwrap()["role"], "relay");
    assert!(
        ManagedRuntime::start(options(dir.path()), Arc::new(native_instance_manager())).is_err()
    );
}
#[cfg(all(feature = "websocket", feature = "smoltcp"))]
#[tokio::test]
async fn relay_self_advertisement_is_signed_and_plain_clients_do_not_advertise() {
    let server = TestAuthority::start(120).await;
    server.state.store(1, Ordering::SeqCst);
    let plain_dir = tempfile::tempdir().unwrap();
    let mut opts = options(plain_dir.path());
    opts.origin = server.origin.clone();
    let mut plain = fixture_client(opts);
    plain.http = server.http.clone();
    plain.cycle().await.unwrap();
    assert_eq!(server.advertisements.load(Ordering::SeqCst), 0);
    plain.stop("test_finished").await.unwrap();
    drop(server);
    let server = TestAuthority::start(120).await;
    server.state.store(1, Ordering::SeqCst);
    let reservation = tokio::net::TcpListener::bind("0.0.0.0:0").await.unwrap();
    let address = reservation.local_addr().unwrap();
    drop(reservation);
    let dir = tempfile::tempdir().unwrap();
    let mut opts = options(dir.path());
    opts.origin = server.origin.clone();
    opts.relay = Some(RelayAdvertisement {
        listeners: vec![format!("tcp://0.0.0.0:{}", address.port())],
        public_peers: vec![format!("tcp://8.8.8.8:{}", address.port())],
        region: "test-global".into(),
    });
    let mut relay = fixture_client(opts);
    relay.http = server.http.clone();
    relay.cycle().await.unwrap();
    // The fixture verifies the real Ed25519 signature BEFORE accepting the body.
    assert_eq!(server.advertisements.load(Ordering::SeqCst), 2);
    assert!(
        !relay
            .manager
            .instance(relay.identity.instance_id)
            .unwrap()
            .running_listeners()
            .is_empty()
    );
    relay.stop("test_finished").await.unwrap();
}

struct NativePayloadReceiver(tokio::sync::mpsc::UnboundedSender<Vec<u8>>);
#[async_trait::async_trait]
impl easytier_core::peers::PeerPacketFilter for NativePayloadReceiver {
    async fn try_process_packet_from_peer(
        &self,
        packet: easytier_core::packet::ZCPacket,
    ) -> Option<easytier_core::packet::ZCPacket> {
        if packet
            .peer_manager_header()
            .is_some_and(|h| h.packet_type == easytier_core::packet::PacketType::Data as u8)
        {
            let _ = self.0.send(packet.payload().to_vec());
            None
        } else {
            Some(packet)
        }
    }
}
fn native_hot_reply(client: &Client, keys: &[(u8, String)], peers: &[String]) -> Reply {
    let time = now().unwrap();
    let credentials:Vec<_>=keys.iter().map(|(key,id)|json!({"credential_id":id,"credential_public_key":STANDARD.encode(PublicKey::from(&StaticSecret::from([*key;32])).as_bytes()),"groups":["members"],"allow_relay":false,"allowed_proxy_cidrs":[],"expiry_unix":time+120,"reusable":false})).collect();
    let config = json!({"ipv4":"10.253.254.1/24","listeners":[],"network_identity":{"network_name":"test-managed"},"secure_mode":{"enabled":true},"flags":{"no_tun":true,"use_smoltcp":true,"enable_ipv6":false,"disable_p2p":true,"disable_upnp":true,"disable_relay_data":true},"peer":peers.iter().map(|uri|json!({"uri":uri})).collect::<Vec<_>>(),"managed_credentials":credentials});
    serde_json::from_value(json!({"version":1,"operation":"sync","request_id":Uuid::new_v4(),"device_id":client.identity.device_id,"state":"approved","role":"leaf","network_id":"test-managed","auth_revision":1,"session_generation":1,"issued_at":time,"expires_at":time+120,"lease_id":"native-hot-lease","config_toml":toml::to_string(&toml::Value::try_from(config).unwrap()).unwrap(),"directory":[{"device_id":client.identity.device_id,"hostname":"fixture","overlay_ip":"10.253.254.1","overlay_public_key":client.identity.overlay_public().unwrap()}]})).unwrap()
}
#[cfg(feature = "smoltcp")]
async fn native_pair_has_connection_and_routes(
    local: &crate::instance::factory::NativeCoreInstance,
    remote: &crate::instance::factory::NativeCoreInstance,
) -> bool {
    // Peer insertion precedes final connection publication and OSPF convergence.
    // Sending by peer ID requires the actual route, not merely a peer-map row.
    let local_connected = local.peer_manager().list_peer_snapshots().await.iter().any(|peer| {
        peer.peer_id == remote.peer_id() && peer.conns.iter().any(|conn| !conn.is_closed)
    });
    let remote_connected = remote.peer_manager().list_peer_snapshots().await.iter().any(|peer| {
        peer.peer_id == local.peer_id() && peer.conns.iter().any(|conn| !conn.is_closed)
    });
    let local_route = local.peer_manager().list_route_snapshots().await.iter().any(|route| {
        route.peer_id == remote.peer_id() && route.next_hop_peer_id == remote.peer_id()
    });
    let remote_route = remote.peer_manager().list_route_snapshots().await.iter().any(|route| {
        route.peer_id == local.peer_id() && route.next_hop_peer_id == local.peer_id()
    });
    local_connected && remote_connected && local_route && remote_route
}

#[cfg(feature = "smoltcp")]
#[tokio::test]
async fn relay_directory_hot_add_remove_preserves_native_instance_connections_and_payloads() {
    use crate::instance::factory::create_native_instance;
    use easytier_core::packet::{PacketType, ZCPacket};
    let dir = tempfile::tempdir().unwrap();
    let mut client = fixture_client(options(dir.path()));
    // Keep native bind_device=true and its anti-overlay underlay policy. In
    // mirrored WSL, 127/8 routes over loopback0 while explicit loopback listeners
    // bind lo, and physical-source connector sockets cannot reach that fixture.
    // A UDP connect selects the real underlay source without sending a packet.
    let route_probe = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
    route_probe.connect("192.0.2.1:9").unwrap();
    let underlay_ip = route_probe.local_addr().unwrap().ip();
    assert!(
        !underlay_ip.is_loopback() && !underlay_ip.is_unspecified(),
        "native underlay fixture needs an actual routed host IPv4 address"
    );
    drop(route_probe);
    let mut remotes = Vec::new();
    let mut uris = Vec::new();
    let mut keys = Vec::new();
    for byte in [25u8, 26] {
        let reservation = tokio::net::TcpListener::bind((underlay_ip, 0))
            .await
            .unwrap();
        let address = reservation.local_addr().unwrap();
        drop(reservation);
        let uri = format!("tcp://{address}");
        let id = Uuid::new_v4();
        let time = now().unwrap();
        let cfg = json!({"instance_id":id,"ipv4":format!("10.253.254.{byte}/24"),"listeners":[uri],"network_identity":{"network_name":"test-managed"},"secure_mode":{"enabled":true,"local_private_key":STANDARD.encode([byte;32])},"flags":{"no_tun":true,"use_smoltcp":true,"enable_ipv6":false,"disable_p2p":true,"disable_upnp":true,"disable_relay_data":true,"managed_peer_auth_required":true},"managed_credentials":[{"credential_id":client.identity.device_id,"credential_public_key":client.identity.overlay_public().unwrap(),"groups":["members"],"allow_relay":false,"allowed_proxy_cidrs":[],"expiry_unix":time+120,"reusable":false}]});
        let cfg = TomlConfig::new_from_str(
            &toml::to_string(&toml::Value::try_from(cfg).unwrap()).unwrap(),
        )
        .unwrap();
        assert!(
            cfg.get_flags().bind_device,
            "fixture must retain native interface binding"
        );
        let remote = create_native_instance(cfg).unwrap();
        remote.start().await.unwrap();
        remotes.push(remote);
        uris.push(uri);
        keys.push((byte, id.to_string()));
    }
    client
        .apply(native_hot_reply(&client, &keys, &uris[..1]))
        .await
        .unwrap();
    let instance = client
        .manager
        .instance(client.identity.instance_id)
        .unwrap();
    tokio::time::timeout(Duration::from_secs(15), async {
        while !native_pair_has_connection_and_routes(&instance, &remotes[0]).await {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap_or_else(|error| {
        // Diagnose the original bounded failure rather than hiding it with a
        // longer timeout. All endpoints and identities here are local fixtures;
        // never dump the private TOML/key material into test output.
        let remote_diagnostics: Vec<_> = remotes
            .iter()
            .map(|remote| {
                format!(
                    "peer={} state={:?} listeners={:?} connectors={:?} recent_events={:?}",
                    remote.peer_id(),
                    remote.state(),
                    remote.running_listeners(),
                    remote.list_connectors(),
                    remote.management_events().into_iter().rev().take(12).collect::<Vec<_>>()
                )
            })
            .collect();
        panic!(
            "initial native connection/route convergence failed within original15s: {error}; clientpeer={} state={:?} expected={:?} connectors={:?} recent_events={:?}; remotes={remote_diagnostics:?}",
            instance.peer_id(),
            instance.state(),
            &uris[..1],
            instance.list_connectors(),
            instance.management_events().into_iter().rev().take(12).collect::<Vec<_>>()
        )
    });
    let primary = instance
        .peer_manager()
        .list_peer_snapshots()
        .await
        .into_iter()
        .find(|p| p.peer_id == remotes[0].peer_id())
        .unwrap();
    let primary_conn = primary.conns[0].conn_id.clone();
    let (sender, mut received) = tokio::sync::mpsc::unbounded_channel();
    instance
        .peer_manager()
        .add_packet_process_pipeline(Box::new(NativePayloadReceiver(sender)))
        .await;
    for (step, peers) in [(0, &uris[..1]), (1, &uris[..]), (2, &uris[..1])] {
        client
            .apply(native_hot_reply(&client, &keys, peers))
            .await
            .unwrap();
        assert!(Arc::ptr_eq(
            &instance,
            &client
                .manager
                .instance(client.identity.instance_id)
                .unwrap()
        ));
        if step == 1 {
            tokio::time::timeout(Duration::from_secs(15), async {
                while !native_pair_has_connection_and_routes(&instance, &remotes[1]).await {
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
            })
            .await
            .unwrap();
        }
        let primary = instance
            .peer_manager()
            .list_peer_snapshots()
            .await
            .into_iter()
            .find(|p| p.peer_id == remotes[0].peer_id())
            .unwrap();
        assert!(primary.conns.iter().any(|c| c.conn_id == primary_conn));
        let mut bytes = vec![0u8; 40];
        bytes[0] = 0x45;
        bytes[2..4].copy_from_slice(&40u16.to_be_bytes());
        bytes[9] = 6;
        bytes[12..16].copy_from_slice(&[10, 253, 254, 25]);
        bytes[16..20].copy_from_slice(&[10, 253, 254, 1]);
        bytes[20..22].copy_from_slice(&45000u16.to_be_bytes());
        bytes[22..24].copy_from_slice(&22u16.to_be_bytes());
        bytes[32] = 0x50;
        bytes[33] = step;
        let mut packet = ZCPacket::new_with_payload(&bytes);
        packet.fill_peer_manager_hdr(
            remotes[0].peer_id(),
            instance.peer_id(),
            PacketType::Data as u8,
        );
        remotes[0]
            .peer_manager()
            .send_msg_for_proxy(packet, instance.peer_id())
            .await
            .unwrap();
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(5), received.recv())
                .await
                .unwrap()
                .unwrap(),
            bytes
        );
    }
    // Removing a discovery connector stops future reconnect intent, not an
    // already authenticated connection or an unrelated active payload stream.
    assert!(instance.list_connectors().len() == 1);
    client.stop("test_finished").await.unwrap();
    for remote in remotes {
        remote.stop().await;
    }
}
