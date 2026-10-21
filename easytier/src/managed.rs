//! Native managed-network enrollment and lease lifecycle. No external core process.
use std::{
    io::Write,
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use crate::instance::factory::NativeInstanceManager;
use anyhow::{Context, ensure};
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use easytier_core::{
    config::toml::{ConfigLoader as _, TomlConfig},
    instance::manager::ConfigFileControl,
};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::{sync::Mutex, task::JoinHandle, time::Instant};
use uuid::Uuid;
use x25519_dalek::{PublicKey, StaticSecret};

const REQUEST_DOMAIN: &[u8] = b"EASYTIER-MANAGED-REQUEST-V1\0";
const RESPONSE_DOMAIN: &[u8] = b"EASYTIER-MANAGED-RESPONSE-V1\0";
const MAX_RESPONSE: usize = 512 * 1024;
const MAX_LEASE: i64 = 300;
const CLOCK_TOLERANCE: i64 = 30;
pub const DEFAULT_ORIGIN: &str = "https://www.itachi.fans";

#[derive(Clone)]
pub struct ManagedOptions {
    pub state_dir: PathBuf,
    pub origin: String,
    pub import_config: Option<PathBuf>,
    pub relay: Option<RelayAdvertisement>,
    pub relay_invitation_file: Option<PathBuf>,
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RelayAdvertisement {
    pub listeners: Vec<String>,
    pub public_peers: Vec<String>,
    pub region: String,
}
impl RelayAdvertisement {
    pub fn validate(&self) -> anyhow::Result<()> {
        ensure!(
            !self.listeners.is_empty()
                && self.listeners.len() <= 8
                && !self.public_peers.is_empty()
                && self.public_peers.len() <= 8,
            "relay requires bounded explicit listeners and public addresses"
        );
        ensure!(
            !self.region.is_empty()
                && self.region.len() <= 64
                && self
                    .region
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b)),
            "invalid relay region"
        );
        for (values, public) in [(&self.listeners, false), (&self.public_peers, true)] {
            let mut seen = std::collections::BTreeSet::new();
            for text in values {
                let uri = url::Url::parse(text)?;
                ensure!(
                    text.len() <= 256
                        && matches!(uri.scheme(), "tcp" | "udp" | "quic" | "ws" | "wss")
                        && uri.port_or_known_default().is_some_and(|v| v > 0)
                        && uri.username().is_empty()
                        && uri.password().is_none()
                        && uri.query().is_none()
                        && uri.fragment().is_none()
                        && matches!(uri.path(), "" | "/"),
                    "relay endpoint must contain only scheme, literal address and explicit port"
                );
                let host = uri
                    .host_str()
                    .context("relay endpoint needs an address")?
                    .trim_matches(['[', ']']);
                let ip: std::net::IpAddr = host
                    .parse()
                    .context("relay endpoint requires a literal IP address")?;
                ensure!(
                    global_relay_ip(ip) || (!public && ip.is_unspecified()),
                    "relay endpoint must be globally reachable or a wildcard listener"
                );
                let canonical_host = match ip {
                    std::net::IpAddr::V4(ip) => ip.to_string(),
                    std::net::IpAddr::V6(ip) => format!("[{ip}]"),
                };
                let canonical = format!(
                    "{}://{}:{}",
                    uri.scheme(),
                    canonical_host,
                    uri.port_or_known_default().unwrap()
                );
                ensure!(
                    *text == canonical,
                    "relay endpoint is not in canonical scheme://literal-IP:port form"
                );
                ensure!(seen.insert(canonical), "duplicate relay endpoint");
            }
        }
        for public in &self.public_peers {
            let public = url::Url::parse(public)?;
            ensure!(
                self.listeners.iter().any(|listener| {
                    url::Url::parse(listener).is_ok_and(|listener| {
                        listener.scheme() == public.scheme()
                            && listener.port_or_known_default() == public.port_or_known_default()
                    })
                }),
                "relay public protocol/port must match a configured listener"
            );
        }
        Ok(())
    }
}
fn global_relay_ip(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v) => {
            let o = v.octets();
            !v.is_private()
                && !v.is_loopback()
                && !v.is_link_local()
                && !v.is_broadcast()
                && !v.is_documentation()
                && !v.is_multicast()
                && !v.is_unspecified()
                && o[0] != 0
                && o[0] < 224
                && !(o[0] == 100 && (64..=127).contains(&o[1]))
                && !(o[0] == 198 && (18..=19).contains(&o[1]))
                && !(o[0] == 192 && o[1] == 0 && o[2] == 0)
        }
        std::net::IpAddr::V6(v) => {
            let s = v.segments();
            s[0] & 0xe000 == 0x2000
                && !(s[0] == 0x2001 && s[1] == 0xdb8)
                && !(s[0] == 0x2001 && s[1] == 2)
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Identity {
    version: u32,
    device_id: Uuid,
    instance_id: Uuid,
    #[serde(default)]
    backbone: bool,
    #[serde(default)]
    relay: bool,
    control_private_key: String,
    overlay_private_key: String,
}
impl Identity {
    fn signing_key(&self) -> anyhow::Result<SigningKey> {
        Ok(SigningKey::from_bytes(&decode32(
            &self.control_private_key,
        )?))
    }
    fn overlay_public(&self) -> anyhow::Result<String> {
        let secret = StaticSecret::from(decode32(&self.overlay_private_key)?);
        Ok(STANDARD.encode(PublicKey::from(&secret).as_bytes()))
    }
    fn public(&self) -> anyhow::Result<Value> {
        Ok(
            json!({"version":1,"device_id":self.device_id,"instance_id":self.instance_id,
            "device_public_key":STANDARD.encode(self.signing_key()?.verifying_key().as_bytes()),
            "overlay_public_key":self.overlay_public()?,"role":if self.backbone {"backbone"} else if self.relay {"relay"} else {"leaf"},"hostname":hostname(),"platform":std::env::consts::OS}),
        )
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Authority {
    version: u32,
    origin: String,
    network_id: String,
    key_id: String,
    public_key: String,
}
#[derive(Deserialize)]
struct Info {
    version: u32,
    network_id: String,
    key_id: String,
    algorithm: String,
    public_key: String,
}
#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Watermark {
    auth_revision: u64,
    session_generation: u64,
}
#[derive(Serialize, Deserialize)]
struct Envelope {
    payload: String,
    signature: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    key_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    algorithm: Option<String>,
}
#[derive(Deserialize)]
struct Reply {
    version: u32,
    operation: String,
    request_id: Uuid,
    device_id: Uuid,
    state: String,
    #[serde(default)]
    role: Option<String>,
    network_id: String,
    auth_revision: u64,
    session_generation: u64,
    issued_at: i64,
    expires_at: i64,
    #[serde(default)]
    lease_id: String,
    #[serde(default)]
    config_revision: Value,
    config_toml: Option<String>,
    challenge: Option<String>,
    challenge_expires_at: Option<i64>,
    #[serde(default)]
    directory: Vec<DirectoryEntry>,
    #[serde(default)]
    telemetry_budget: Value,
    #[serde(default)]
    telemetry_accepted: bool,
}
#[derive(Serialize, Deserialize)]
struct DirectoryEntry {
    device_id: Uuid,
    hostname: String,
    overlay_ip: String,
    overlay_public_key: String,
}

fn now() -> anyhow::Result<i64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_secs()
        .try_into()?)
}
fn hostname() -> String {
    gethostname::gethostname()
        .to_string_lossy()
        .chars()
        .take(128)
        .collect()
}
fn decode32(value: &str) -> anyhow::Result<[u8; 32]> {
    let raw = STANDARD
        .decode(value)
        .context("invalid identity key encoding")?;
    ensure!(
        STANDARD.encode(&raw) == value,
        "noncanonical identity key encoding"
    );
    raw.try_into()
        .map_err(|_| anyhow::anyhow!("identity key must contain 32 bytes"))
}
fn prepare_dir(dir: &Path) -> anyhow::Result<()> {
    #[cfg(windows)]
    let created = !dir.exists();
    if !dir.exists() {
        std::fs::create_dir_all(dir)?;
    }
    ensure!(
        !std::fs::symlink_metadata(dir)?.file_type().is_symlink(),
        "managed state must not be a symlink"
    );
    #[cfg(windows)]
    restrict_windows_access(dir, created)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        ensure!(
            std::fs::metadata(dir)?.uid() == unsafe { nix::libc::geteuid() },
            "managed state has another owner"
        );
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}
#[cfg(windows)]
fn restrict_windows_access(path: &Path, created: bool) -> anyhow::Result<()> {
    // Managed Windows TUN/service installation is privileged. Match the
    // installer's exact SYSTEM+Administrators DACL and explicit BA ownership.
    // Existing foreign-owned objects are never silently taken over.
    use std::{ffi::c_void, os::windows::ffi::OsStrExt};
    #[link(name = "advapi32")]
    unsafe extern "system" {
        fn GetNamedSecurityInfoW(
            name: *const u16,
            kind: u32,
            information: u32,
            owner: *mut *mut c_void,
            group: *mut *mut c_void,
            dacl: *mut *mut c_void,
            sacl: *mut *mut c_void,
            descriptor: *mut *mut c_void,
        ) -> u32;
        fn ConvertStringSecurityDescriptorToSecurityDescriptorW(
            text: *const u16,
            revision: u32,
            descriptor: *mut *mut c_void,
            size: *mut u32,
        ) -> i32;
        fn GetSecurityDescriptorOwner(
            descriptor: *const c_void,
            owner: *mut *mut c_void,
            defaulted: *mut i32,
        ) -> i32;
        fn GetSecurityDescriptorDacl(
            descriptor: *const c_void,
            present: *mut i32,
            dacl: *mut *mut c_void,
            defaulted: *mut i32,
        ) -> i32;
        fn ConvertSidToStringSidW(sid: *const c_void, text: *mut *mut u16) -> i32;
        fn SetNamedSecurityInfoW(
            name: *const u16,
            kind: u32,
            information: u32,
            owner: *const c_void,
            group: *const c_void,
            dacl: *const c_void,
            sacl: *const c_void,
        ) -> u32;
    }
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn LocalFree(value: *mut c_void) -> *mut c_void;
    }
    let name: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    unsafe {
        if !created {
            let mut owner = std::ptr::null_mut();
            let mut descriptor = std::ptr::null_mut();
            let code = GetNamedSecurityInfoW(
                name.as_ptr(),
                1,
                1,
                &mut owner,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut descriptor,
            );
            if code != 0 {
                return Err(std::io::Error::from_raw_os_error(code as i32).into());
            }
            let mut text = std::ptr::null_mut();
            let converted = ConvertSidToStringSidW(owner, &mut text);
            let sid = if converted != 0 {
                let mut length = 0;
                while *text.add(length) != 0 {
                    length += 1;
                }
                String::from_utf16_lossy(std::slice::from_raw_parts(text, length))
            } else {
                String::new()
            };
            if !text.is_null() {
                LocalFree(text.cast());
            }
            if !descriptor.is_null() {
                LocalFree(descriptor);
            }
            ensure!(
                sid == "S-1-5-18" || sid == "S-1-5-32-544",
                "managed Windows state must be owned by SYSTEM or Administrators"
            );
        }
        let sddl: Vec<u16> = "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)\0"
            .encode_utf16()
            .collect();
        let mut descriptor = std::ptr::null_mut();
        ensure!(
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                1,
                &mut descriptor,
                std::ptr::null_mut()
            ) != 0,
            "cannot construct private Windows security descriptor"
        );
        let result = (|| -> anyhow::Result<()> {
            let mut owner = std::ptr::null_mut();
            let mut defaulted = 0;
            let mut present = 0;
            let mut dacl = std::ptr::null_mut();
            ensure!(
                GetSecurityDescriptorOwner(descriptor, &mut owner, &mut defaulted) != 0,
                "cannot read private Windows owner"
            );
            ensure!(
                GetSecurityDescriptorDacl(descriptor, &mut present, &mut dacl, &mut defaulted) != 0
                    && present != 0
                    && !dacl.is_null(),
                "cannot read private Windows DACL"
            );
            let code = SetNamedSecurityInfoW(
                name.as_ptr(),
                1,
                1 | 4 | 0x80000000,
                owner,
                std::ptr::null(),
                dacl,
                std::ptr::null(),
            );
            if code != 0 {
                return Err(std::io::Error::from_raw_os_error(code as i32).into());
            }
            Ok(())
        })();
        LocalFree(descriptor);
        result
    }
}
fn read_private(path: &Path) -> anyhow::Result<Vec<u8>> {
    let metadata = std::fs::symlink_metadata(path)?;
    ensure!(
        metadata.is_file() && !metadata.file_type().is_symlink(),
        "managed state must be a regular file"
    );
    #[cfg(windows)]
    restrict_windows_access(path, false)?;
    ensure!(
        metadata.len() <= MAX_RESPONSE as u64,
        "managed state too large"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        ensure!(
            metadata.permissions().mode() & 0o077 == 0,
            "managed state permissions are not private"
        );
        ensure!(
            metadata.uid() == unsafe { nix::libc::geteuid() },
            "managed state file has another owner"
        );
    }
    Ok(std::fs::read(path)?)
}
fn persist<T: Serialize>(path: &Path, value: &T) -> anyhow::Result<()> {
    let temporary = path.with_extension(format!("{}.tmp", Uuid::new_v4()));
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let result = (|| -> anyhow::Result<()> {
        let mut file = options.open(&temporary)?;
        #[cfg(windows)]
        restrict_windows_access(&temporary, true)?;
        file.write_all(&serde_json::to_vec(value)?)?;
        file.sync_all()?;
        std::fs::rename(&temporary, path)?;
        #[cfg(unix)]
        {
            std::fs::File::open(path.parent().unwrap())?.sync_all()?;
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    result
}
fn imported(path: &Path) -> anyhow::Result<(Uuid, String, bool)> {
    let cfg = TomlConfig::new_from_str(std::str::from_utf8(&read_private(path)?)?)?;
    let key = cfg
        .get_secure_mode()
        .and_then(|v| v.local_private_key)
        .context("import config requires an existing secure-mode private key")?;
    decode32(&key)?;
    Ok((
        cfg.get_id(),
        key,
        cfg.get_network_identity()
            .network_secret
            .is_some_and(|v| !v.is_empty()),
    ))
}
fn load_identity(options: &ManagedOptions) -> anyhow::Result<Identity> {
    prepare_dir(&options.state_dir)?;
    let _identity_lock = lock_named(&options.state_dir, "identity.lock")?;
    let path = options.state_dir.join("identity.json");
    if let Some(relay) = &options.relay {
        relay.validate()?;
    }
    ensure!(
        options.relay_invitation_file.is_none() || options.relay.is_some(),
        "relay invitation requires explicit relay intent"
    );
    let identity = if path.exists() {
        let mut value: Identity = serde_json::from_slice(&read_private(&path)?)?;
        ensure!(value.version == 1, "unsupported identity state");
        if let Some(import) = &options.import_config {
            let (id, key, backbone) = imported(import)?;
            ensure!(
                id == value.instance_id
                    && key == value.overlay_private_key
                    && backbone == value.backbone,
                "import would replace an existing identity"
            );
        }
        if options.relay.is_some() && !value.relay {
            ensure!(
                !value.backbone,
                "a backbone identity cannot silently change into a relay"
            );
            value.relay = true;
            persist(&path, &value)?;
        }
        value
    } else {
        let mut control = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut control);
        let (id, overlay, backbone) = if let Some(path) = &options.import_config {
            imported(path)?
        } else {
            let mut key = [0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut key);
            (Uuid::new_v4(), STANDARD.encode(key), false)
        };
        ensure!(
            !(backbone && options.relay.is_some()),
            "backbone and relay intent are distinct"
        );
        let value = Identity {
            version: 1,
            device_id: id,
            instance_id: id,
            backbone,
            relay: options.relay.is_some(),
            control_private_key: STANDARD.encode(control),
            overlay_private_key: overlay,
        };
        persist(&path, &value)?;
        value
    };
    identity.signing_key()?;
    identity.overlay_public()?;
    persist(
        &options.state_dir.join("public-identity.json"),
        &identity.public()?,
    )?;
    Ok(identity)
}
/// Creates local keys/imports an existing identity, without network access or starting a TUN.
pub fn status(options: &ManagedOptions) -> anyhow::Result<Value> {
    load_identity(options)?.public()
}

fn origin(value: &str) -> anyhow::Result<url::Url> {
    let parsed = url::Url::parse(value)?;
    ensure!(
        parsed.scheme() == "https" && parsed.host_str().is_some(),
        "managed origin requires HTTPS"
    );
    ensure!(
        parsed.username().is_empty()
            && parsed.password().is_none()
            && parsed.query().is_none()
            && parsed.fragment().is_none(),
        "managed origin cannot contain credentials, query or fragment"
    );
    ensure!(
        parsed.path() == "/",
        "managed origin must not contain a path"
    );
    Ok(parsed)
}

struct ActiveLease {
    id: Uuid,
    deadline: Instant,
}
type Active = Arc<Mutex<Option<ActiveLease>>>;
pub struct ManagedRuntime {
    task: JoinHandle<()>,
    watchdog: JoinHandle<()>,
    manager: Arc<NativeInstanceManager>,
    active: Active,
    lifecycle: Arc<Mutex<()>>,
    state_dir: PathBuf,
    _lock: std::fs::File,
}
fn lock_state(dir: &Path) -> anyhow::Result<std::fs::File> {
    lock_named(dir, "runtime.lock")
}
fn lock_named(dir: &Path, name: &str) -> anyhow::Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true).write(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(nix::libc::O_NOFOLLOW);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.share_mode(0);
    }
    let path = dir.join(name);
    #[cfg(windows)]
    let created = !path.exists();
    let file = options.open(&path)?;
    #[cfg(windows)]
    restrict_windows_access(&path, created)?;
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;
        ensure!(
            unsafe { nix::libc::flock(file.as_raw_fd(), nix::libc::LOCK_EX | nix::libc::LOCK_NB) }
                == 0,
            "managed state is already in use"
        );
    }
    Ok(file)
}
impl ManagedRuntime {
    pub fn start(
        options: ManagedOptions,
        manager: Arc<NativeInstanceManager>,
    ) -> anyhow::Result<Self> {
        let http = reqwest::Client::builder()
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(10))
            .build()?;
        Self::start_with_http(options, manager, http)
    }
    fn start_with_http(
        options: ManagedOptions,
        manager: Arc<NativeInstanceManager>,
        http: reqwest::Client,
    ) -> anyhow::Result<Self> {
        let url = origin(&options.origin)?;
        prepare_dir(&options.state_dir)?;
        let lock = lock_state(&options.state_dir)?;
        let identity = load_identity(&options)?;
        ensure!(
            identity.relay == options.relay.is_some(),
            "persisted relay intent requires explicit relay listener/advertisement options"
        );
        ensure!(
            !(identity.backbone && identity.relay),
            "backbone and relay intent are distinct"
        );
        let watermark = if options.state_dir.join("watermark.json").exists() {
            serde_json::from_slice(&read_private(&options.state_dir.join("watermark.json"))?)?
        } else {
            ensure!(
                !options.state_dir.join("authority.json").exists(),
                "trusted authority state is missing its anti-rollback watermark"
            );
            let fresh = Watermark::default();
            persist(&options.state_dir.join("watermark.json"), &fresh)?;
            fresh
        };
        ensure!(
            (watermark.auth_revision == 0 && watermark.session_generation == 0)
                || options.state_dir.join("authority.json").exists(),
            "established managed watermark is missing its authority pin"
        );
        let active: Active = Arc::new(Mutex::new(None));
        let lifecycle = Arc::new(Mutex::new(()));
        let monitor_lifecycle = lifecycle.clone();
        let monitor_state = options.state_dir.clone();
        let monitor_active = active.clone();
        let monitor_manager = manager.clone();
        let watchdog = tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_millis(250));
            loop {
                tick.tick().await;
                let _operation = monitor_lifecycle.lock().await;
                let expired = {
                    let live = monitor_active.lock().await;
                    if live
                        .as_ref()
                        .is_some_and(|lease| Instant::now() >= lease.deadline)
                    {
                        live.as_ref().map(|v| v.id)
                    } else {
                        None
                    }
                };
                if let Some(id) = expired {
                    if let Err(error) = monitor_manager.delete_network_instances([id]).await {
                        tracing::error!(%error,"managed expiry removal failed; retrying fail-closed removal");
                        continue;
                    }
                    if monitor_manager.instance(id).is_some() {
                        continue;
                    }
                    monitor_active.lock().await.take();
                    if let Err(error) = persist(
                        &monitor_state.join("status.json"),
                        &json!({"state":"expired","instance_id":id}),
                    ) {
                        tracing::error!(%error,"managed expiry status failed");
                    }
                }
            }
        });
        let mut client = Client {
            options,
            url,
            http,
            identity,
            watermark,
            authority: None,
            manager: manager.clone(),
            active: active.clone(),
            lifecycle: lifecycle.clone(),
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
        };
        let client_state = client.options.state_dir.clone();
        let task = tokio::spawn(async move {
            loop {
                if client.cycle().await.is_err() {
                    // Config parser errors may contain private TOML source spans.
                    tracing::warn!(
                        "managed synchronization failed; existing lease is not extended; private error details suppressed"
                    );
                }
                tokio::time::sleep(Duration::from_secs(
                    25 + u64::from(rand::random::<u8>() % 11),
                ))
                .await;
            }
        });
        Ok(Self {
            task,
            watchdog,
            manager,
            active,
            lifecycle,
            state_dir: client_state,
            _lock: lock,
        })
    }
    pub async fn shutdown(&self) -> anyhow::Result<()> {
        self.task.abort();
        self.watchdog.abort();
        let _operation = self.lifecycle.lock().await;
        if let Some(active) = self.active.lock().await.take() {
            self.manager.delete_network_instances([active.id]).await?;
        }
        persist(
            &self.state_dir.join("status.json"),
            &json!({"state":"stopped"}),
        )?;
        Ok(())
    }
}
impl Drop for ManagedRuntime {
    fn drop(&mut self) {
        self.task.abort();
        self.watchdog.abort();
    }
}

struct PendingTelemetry {
    report: Value,
    sequence: u64,
    fingerprint: String,
    expires_at: i64,
}

struct Client {
    options: ManagedOptions,
    url: url::Url,
    http: reqwest::Client,
    identity: Identity,
    watermark: Watermark,
    authority: Option<Authority>,
    manager: Arc<NativeInstanceManager>,
    active: Active,
    lifecycle: Arc<Mutex<()>>,
    stable_config: Option<toml::Value>,
    peer_urls: std::collections::BTreeSet<String>,
    telemetry_credit: usize,
    telemetry_last: Instant,
    telemetry_last_fingerprint: Option<String>,
    telemetry_sequence: u64,
    telemetry_boot: Option<String>,
    telemetry_rate: usize,
    telemetry_pending: Option<PendingTelemetry>,
    telemetry_expired_batches: u64,
    telemetry_failed_attempts: u64,
    telemetry_round: usize,
}
impl Client {
    async fn bounded_response(response: reqwest::Response) -> anyhow::Result<Vec<u8>> {
        ensure!(
            response.status().is_success(),
            "managed authority rejected request ({})",
            response.status()
        );
        ensure!(
            response
                .content_length()
                .is_none_or(|v| v <= MAX_RESPONSE as u64),
            "managed response too large"
        );
        let mut response = response;
        let mut data = Vec::new();
        while let Some(chunk) = response.chunk().await? {
            ensure!(
                data.len() + chunk.len() <= MAX_RESPONSE,
                "managed response too large"
            );
            data.extend_from_slice(&chunk);
        }
        Ok(data)
    }
    async fn discover(&mut self) -> anyhow::Result<()> {
        if self.authority.is_some() {
            return Ok(());
        }
        let info: Info = serde_json::from_slice(
            &Self::bounded_response(
                self.http
                    .get(self.url.join("api/easytier/info")?)
                    .send()
                    .await?,
            )
            .await?,
        )?;
        ensure!(
            info.version == 1
                && info.algorithm == "Ed25519"
                && !info.key_id.is_empty()
                && !info.network_id.is_empty(),
            "invalid managed authority information"
        );
        VerifyingKey::from_bytes(&decode32(&info.public_key)?)?;
        let candidate = Authority {
            version: 1,
            origin: self.url.to_string(),
            network_id: info.network_id,
            key_id: info.key_id,
            public_key: info.public_key,
        };
        let path = self.options.state_dir.join("authority.json");
        if path.exists() {
            let saved: Authority = serde_json::from_slice(&read_private(&path)?)?;
            ensure!(
                saved.version == 1
                    && saved.origin == candidate.origin
                    && saved.network_id == candidate.network_id
                    && saved.key_id == candidate.key_id
                    && saved.public_key == candidate.public_key,
                "managed authority identity changed; explicit trust migration required"
            );
        } else {
            ensure!(
                self.watermark.auth_revision == 0 && self.watermark.session_generation == 0,
                "established managed identity cannot repin a missing authority"
            );
            persist(&path, &candidate)?;
        }
        self.authority = Some(candidate);
        Ok(())
    }
    async fn request(
        &self,
        operation: &str,
        generation: u64,
        challenge: &str,
        body: Value,
    ) -> anyhow::Result<Reply> {
        let request_id = Uuid::new_v4();
        let raw = serde_json::to_vec(
            &json!({"version":1,"operation":operation,"device_id":self.identity.device_id,"request_id":request_id,
            "issued_at":now()?,"session_generation":generation,"sequence":if operation=="sync" {1}else{0},"challenge":challenge,"body":body}),
        )?;
        let mut message = REQUEST_DOMAIN.to_vec();
        message.extend_from_slice(&raw);
        let envelope = Envelope {
            payload: URL_SAFE_NO_PAD.encode(raw),
            signature: URL_SAFE_NO_PAD
                .encode(self.identity.signing_key()?.sign(&message).to_bytes()),
            key_id: None,
            algorithm: None,
        };
        let response = Self::bounded_response(
            self.http
                .post(self.url.join(&format!("api/easytier/{operation}"))?)
                .json(&envelope)
                .send()
                .await?,
        )
        .await?;
        self.verify_reply(&response, operation, request_id, generation)
    }
    fn verify_reply(
        &self,
        bytes: &[u8],
        operation: &str,
        request_id: Uuid,
        generation: u64,
    ) -> anyhow::Result<Reply> {
        let envelope: Envelope = serde_json::from_slice(bytes)?;
        let authority = self.authority.as_ref().context("authority not pinned")?;
        ensure!(
            envelope.algorithm.as_deref() == Some("Ed25519")
                && envelope.key_id.as_deref() == Some(authority.key_id.as_str()),
            "response signing identity mismatch"
        );
        let raw = URL_SAFE_NO_PAD.decode(&envelope.payload)?;
        ensure!(
            raw.len() <= MAX_RESPONSE && URL_SAFE_NO_PAD.encode(&raw) == envelope.payload,
            "invalid response payload encoding"
        );
        let signature = Signature::from_slice(&URL_SAFE_NO_PAD.decode(&envelope.signature)?)?;
        let mut message = RESPONSE_DOMAIN.to_vec();
        message.extend_from_slice(&raw);
        VerifyingKey::from_bytes(&decode32(&authority.public_key)?)?
            .verify_strict(&message, &signature)?;
        let reply: Reply = serde_json::from_slice(&raw)?;
        let time = now()?;
        ensure!(
            reply.version == 1
                && reply.operation == operation
                && reply.request_id == request_id
                && reply.device_id == self.identity.device_id
                && reply.network_id == authority.network_id,
            "response binding mismatch"
        );
        ensure!(
            ["pending", "approved", "revoked"].contains(&reply.state.as_str()),
            "unknown managed state"
        );
        ensure!(
            reply.issued_at >= time - 60 && reply.issued_at <= time + CLOCK_TOLERANCE,
            "managed response time outside freshness window"
        );
        ensure!(
            reply.auth_revision >= self.watermark.auth_revision,
            "authorization revision rollback"
        );
        if operation == "challenge" {
            ensure!(
                reply.session_generation > self.watermark.session_generation
                    || reply.state == "revoked",
                "session generation rollback"
            );
        } else {
            ensure!(
                reply.session_generation == generation,
                "response generation mismatch"
            );
        }
        if reply.state == "approved" && operation == "sync" {
            ensure!(
                !reply.lease_id.is_empty()
                    && reply.expires_at > time
                    && reply.expires_at > reply.issued_at
                    && reply.expires_at - reply.issued_at <= MAX_LEASE,
                "invalid managed lease lifetime"
            );
        }
        Ok(reply)
    }
    async fn stop(&mut self, state: &str) -> anyhow::Result<()> {
        let _operation = self.lifecycle.lock().await;
        self.active.lock().await.take();
        self.manager
            .delete_network_instances([self.identity.instance_id])
            .await?;
        self.stable_config = None;
        self.peer_urls.clear();
        persist(
            &self.options.state_dir.join("status.json"),
            &json!({"state":state,"device_id":self.identity.device_id,"auth_revision":self.watermark.auth_revision}),
        )?;
        Ok(())
    }
    fn relay_body(&self) -> anyhow::Result<Option<Value>> {
        let Some(relay) = &self.options.relay else {
            return Ok(None);
        };
        relay.validate()?;
        let mut value = serde_json::to_value(relay)?;
        if let Some(path) = &self.options.relay_invitation_file {
            let raw = read_private(path)?;
            ensure!(raw.len() <= 2048, "relay invitation file too large");
            let token = std::str::from_utf8(&raw)?.trim();
            ensure!(
                (16..=1024).contains(&token.len())
                    && token
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b)),
                "invalid relay invitation encoding"
            );
            value["invitation"] = json!(token);
        }
        Ok(Some(value))
    }
    async fn cycle(&mut self) -> anyhow::Result<()> {
        self.discover().await?;
        // Idempotent enrollment advertises public identities only; approval is server-side.
        let public = self.identity.public()?;
        let mut enroll_body = json!({"device_public_key":public["device_public_key"],"overlay_public_key":public["overlay_public_key"],"hostname":hostname(),"platform":std::env::consts::OS});
        if let Some(relay) = self.relay_body()? {
            enroll_body["relay"] = relay;
        }
        let enrolled = self.request("enroll", 0, "", enroll_body).await?;
        if enrolled.state == "revoked" {
            self.watermark.auth_revision = enrolled.auth_revision;
            persist(
                &self.options.state_dir.join("watermark.json"),
                &self.watermark,
            )?;
            return self.stop("revoked").await;
        }
        let challenged = self.request("challenge", 0, "", json!({})).await?;
        if challenged.state == "revoked" {
            self.watermark.auth_revision = challenged.auth_revision;
            persist(
                &self.options.state_dir.join("watermark.json"),
                &self.watermark,
            )?;
            return self.stop("revoked").await;
        }
        let challenge = challenged
            .challenge
            .as_deref()
            .context("missing managed challenge")?;
        ensure!(
            challenge.len() >= 16
                && challenge.len() <= 256
                && challenged.challenge_expires_at.is_some_and(
                    |v| v > now().unwrap_or(i64::MAX) && v - challenged.issued_at <= 30
                ),
            "invalid managed challenge lifetime"
        );
        self.watermark.session_generation = challenged.session_generation;
        self.watermark.auth_revision = challenged.auth_revision;
        persist(
            &self.options.state_dir.join("watermark.json"),
            &self.watermark,
        )?;
        let (telemetry, report_pending) = self.telemetry().await?;
        let mut sync_body = json!({"hostname":hostname(),"platform":std::env::consts::OS});
        if let Some(relay) = self.relay_body()? {
            sync_body["relay"] = relay;
        }
        if !telemetry.is_null() {
            sync_body["telemetry"] = telemetry;
        }
        let reply = match self
            .request("sync", challenged.session_generation, challenge, sync_body)
            .await
        {
            Ok(reply) => reply,
            Err(error) => {
                self.telemetry_failed_attempts = self.telemetry_failed_attempts.saturating_add(1);
                return Err(error);
            }
        };
        if report_pending && reply.state == "approved" && reply.telemetry_accepted {
            if let Some(pending) = self.telemetry_pending.take() {
                self.telemetry_round = self.telemetry_round.wrapping_add(1);
                self.telemetry_sequence = pending.sequence;
                self.telemetry_last_fingerprint = Some(pending.fingerprint);
            }
        }
        self.watermark.auth_revision = reply.auth_revision;
        if let Some(rate) = reply
            .telemetry_budget
            .get("bytes_per_minute")
            .and_then(Value::as_u64)
        {
            self.telemetry_rate = (rate.min(16384)) as usize;
            self.telemetry_credit = self.telemetry_credit.min(self.telemetry_rate);
        }
        persist(
            &self.options.state_dir.join("watermark.json"),
            &self.watermark,
        )?;
        if reply.state != "approved" {
            return self.stop(&reply.state).await;
        }
        self.apply(reply).await
    }
    fn health_report(&mut self, report: Value) -> (Value, bool) {
        let size = serde_json::to_vec(&report)
            .map(|v| ((v.len() + 2) / 3) * 4)
            .unwrap_or(usize::MAX);
        if size <= self.telemetry_credit {
            self.telemetry_credit -= size;
            (report, false)
        } else {
            (Value::Null, false)
        }
    }
    async fn telemetry(&mut self) -> anyhow::Result<(Value, bool)> {
        let time = now()?;
        if self
            .telemetry_pending
            .as_ref()
            .is_some_and(|p| p.expires_at <= time)
        {
            self.telemetry_pending = None;
            self.telemetry_expired_batches = self.telemetry_expired_batches.saturating_add(1);
        }
        let expired = self.telemetry_expired_batches;
        let failed = self.telemetry_failed_attempts;
        let empty = |state: &str| json!({"measured_at":time,"expires_at":time+120,"flows":[],"links":[],"routes":[],"coverage":{"state":state,"expired_unacknowledged_batches":expired,"failed_sync_attempts":failed,"full_path_status":"unknown_endpoint_observations_only"}});
        if self.telemetry_rate == 0 {
            return Ok((Value::Null, false));
        }
        let elapsed = self.telemetry_last.elapsed().as_secs_f64();
        self.telemetry_credit = (self.telemetry_credit
            + (elapsed * self.telemetry_rate as f64 / 60.0) as usize)
            .min(self.telemetry_rate);
        self.telemetry_last = Instant::now();
        if self.telemetry_pending.is_none() {
            let Some(instance) = self.manager.instance(self.identity.instance_id) else {
                return Ok(self.health_report(empty("no_instance")));
            };
            let header = instance.peer_manager().service_flow_snapshot(0);
            let boot = header.boot_id.to_string();
            if self.telemetry_boot.as_ref() != Some(&boot) {
                self.telemetry_sequence = 0;
                self.telemetry_boot = Some(boot);
                self.telemetry_last_fingerprint = None;
            }
            let mut snapshot = serde_json::to_value(
                instance
                    .peer_manager()
                    .service_flow_snapshot_since(4, self.telemetry_sequence),
            )?;
            // Native connection tuples and statistics are actual local observations;
            // they do not prove a complete end-to-end route or bandwidth.
            let mut conns = Vec::new();
            for peer in instance.peer_manager().list_peer_snapshots().await {
                for conn in peer.conns {
                    let Some(tunnel) = conn.tunnel else { continue };
                    let endpoint = |s: Option<easytier_proto::common::Url>| {
                        s.and_then(|v|url::Url::parse(&v.url).ok()).map(|v|json!({"scheme":v.scheme(),"host":v.host_str(),"port":v.port_or_known_default()})).unwrap_or(Value::Null)
                    };
                    let protocol = match tunnel.tunnel_type.as_str() {
                        "tcp" | "udp" | "quic" | "ws" | "wss" | "wireguard" => {
                            tunnel.tunnel_type.clone()
                        }
                        _ => "unknown".into(),
                    };
                    let stats=conn.stats.map(|v|json!({"rx_bytes":v.rx_bytes,"tx_bytes":v.tx_bytes,"rx_packets":v.rx_packets,"tx_packets":v.tx_packets,"latency_us":v.latency_us}));
                    conns.push(json!({"connection_id":conn.conn_id,"peer_id":conn.peer_id,"my_peer_id":conn.my_peer_id,"protocol":protocol,"tunnel_type":tunnel.tunnel_type,"local_endpoint":endpoint(tunnel.local_addr),"remote_endpoint":endpoint(tunnel.remote_addr),"resolved_remote_endpoint":endpoint(tunnel.resolved_remote_addr),"stats":stats,"is_closed":conn.is_closed,"measured_at":time,"expires_at":time+60,"evidence":"native_peer_connection_snapshot","byte_semantics":"native_connection_counters_not_application_payload"}));
                }
            }
            conns.sort_by_key(|v| v["connection_id"].as_str().unwrap_or("").to_owned());
            let link_total = conns.len();
            let connection_rows: Vec<_> = if link_total == 0 {
                Vec::new()
            } else {
                (0..link_total.min(2))
                    .map(|i| conns[(self.telemetry_round.wrapping_mul(2) + i) % link_total].clone())
                    .collect()
            };
            let mut native_routes = instance.peer_manager().list_route_snapshots().await;
            native_routes.sort_by_key(|v| v.peer_id);
            let route_total = native_routes.len();
            let route_rows: Vec<_> = if route_total == 0 {
                Vec::new()
            } else {
                (0..route_total.min(2)).map(|i|{let route=&native_routes[(self.telemetry_round.wrapping_mul(2)+i)%route_total];json!({"route_id":format!("{}:{}",instance.peer_manager().my_peer_id(),route.peer_id),"peer_id":route.peer_id,"next_hop_peer_id":route.next_hop_peer_id,"cost":route.cost,"path_latency":route.path_latency,"instance_id":route.inst_id,"measured_at":time,"expires_at":time+60,"evidence":"native_computed_route_not_packet_trace","bandwidth":"unknown"})}).collect()
            };
            let fingerprint = serde_json::to_string(
                &json!({"flows":snapshot.get("flows"),"received_attachments":snapshot.get("received_attachments"),"connections":connection_rows,"routes":route_rows,"evicted_idle_flows":snapshot.get("evicted_idle_flows"),"dropped_capacity_samples":snapshot.get("dropped_capacity_samples")}),
            )?;
            if self.telemetry_last_fingerprint.as_ref() == Some(&fingerprint) {
                return Ok(self.health_report(empty("unchanged_no_refresh")));
            }
            let sequence = snapshot
                .get("sequence")
                .and_then(Value::as_u64)
                .unwrap_or(self.telemetry_sequence);
            let table = snapshot
                .as_object_mut()
                .context("invalid native telemetry snapshot")?;
            let flows = table.remove("flows").unwrap_or_else(|| json!([]));
            let mut links = table
                .remove("received_attachments")
                .and_then(|v| v.as_array().cloned())
                .unwrap_or_default();
            links.extend(connection_rows);
            table.insert("connection_sample_total".into(), json!(link_total));
            table.insert("route_sample_total".into(), json!(route_total));
            table.insert("expired_unacknowledged_batches".into(), json!(expired));
            table.insert("failed_sync_attempts".into(), json!(failed));
            let report = json!({"measured_at":time,"expires_at":time+120,"flows":flows,"links":links,"routes":route_rows,"coverage":snapshot});
            self.telemetry_pending = Some(PendingTelemetry {
                report,
                sequence,
                fingerprint,
                expires_at: time + 120,
            });
        }
        let pending = self.telemetry_pending.as_ref().unwrap();
        // Debit every transmission attempt, not just successful acknowledgements.
        // This counts the application report after envelope base64 expansion; TLS/IP overhead is not inferred.
        let size = ((serde_json::to_vec(&pending.report)?.len() + 2) / 3) * 4;
        if size > self.telemetry_credit {
            return Ok(self.health_report(empty("budget_limited")));
        }
        self.telemetry_credit -= size;
        Ok((pending.report.clone(), true))
    }
    async fn apply(&mut self, reply: Reply) -> anyhow::Result<()> {
        let operation = self.lifecycle.clone();
        let guard = operation.lock().await;
        let own = reply
            .directory
            .iter()
            .find(|v| v.device_id == self.identity.device_id)
            .context("approved directory does not bind this device")?;
        ensure!(
            own.overlay_public_key == self.identity.overlay_public()?,
            "approved directory changed the overlay key"
        );
        let text = reply
            .config_toml
            .as_deref()
            .context("approved reply has no configuration")?;
        let mut value: toml::Value = toml::from_str(text)
            .map_err(|_| anyhow::anyhow!("invalid managed TOML configuration"))?;
        let table = value
            .as_table_mut()
            .context("managed config must be a table")?;
        table.insert(
            "instance_id".into(),
            toml::Value::String(self.identity.instance_id.to_string()),
        );
        table.insert("secure_mode".into(),toml::Value::try_from(json!({"enabled":true,"local_private_key":self.identity.overlay_private_key,"local_public_key":self.identity.overlay_public()?}))?);
        let flags = table
            .entry("flags")
            .or_insert_with(|| toml::Value::Table(Default::default()))
            .as_table_mut()
            .context("managed flags must be a table")?;
        flags.insert(
            "managed_peer_auth_required".into(),
            toml::Value::Boolean(true),
        );
        ensure!(
            ["credential_file", "netns", "file_logger", "source"]
                .iter()
                .all(|key| !table.contains_key(*key)),
            "managed config may not select arbitrary state paths/namespaces"
        );
        let cfg = TomlConfig::new_from_str(&toml::to_string(&value)?)
            .map_err(|_| anyhow::anyhow!("invalid managed native configuration"))?;
        ensure!(
            cfg.get_ipv4()
                .is_some_and(|ip| ip.address().to_string() == own.overlay_ip),
            "directory/config address mismatch"
        );
        let expected_role = if self.identity.backbone {
            "backbone"
        } else if self.identity.relay {
            "relay"
        } else {
            "leaf"
        };
        ensure!(
            reply.role.as_deref() == Some(expected_role),
            "signed role does not match explicit local role intent"
        );
        if self.identity.relay {
            let relay = self
                .options
                .relay
                .as_ref()
                .context("relay options missing")?;
            let actual: std::collections::BTreeSet<_> = cfg
                .get_listeners()
                .unwrap_or_default()
                .into_iter()
                .map(|v| v.to_string())
                .collect();
            let expected: std::collections::BTreeSet<_> = relay
                .listeners
                .iter()
                .map(|v| url::Url::parse(v).map(|u| u.to_string()))
                .collect::<Result<_, _>>()?;
            ensure!(
                actual == expected && !cfg.get_flags().disable_relay_data,
                "relay listener/forwarding configuration does not match local relay intent"
            );
        } else if !self.identity.backbone {
            ensure!(
                cfg.get_listeners().unwrap_or_default().is_empty()
                    && cfg.get_flags().disable_relay_data,
                "ordinary managed client cannot be silently made into a relay"
            );
        }
        let role_is_backbone = cfg
            .get_network_identity()
            .network_secret
            .as_ref()
            .is_some_and(|v| !v.is_empty());
        ensure!(
            role_is_backbone == self.identity.backbone,
            "authority attempted to change the locally enrolled backbone role"
        );
        for key in cfg.get_managed_credentials() {
            ensure!(
                key.credential_secret.is_empty() && key.credential_public_key.is_some(),
                "managed peer allowlist must be public-key-only"
            );
            ensure!(
                key.expiry_unix <= now()? + MAX_LEASE && key.expiry_unix > now()?,
                "managed peer identity has invalid active lease expiry"
            );
        }

        let mut stable = value.clone();
        let stable_table = stable.as_table_mut().unwrap();
        stable_table.remove("managed_credentials");
        stable_table.remove("acl");
        // Pinned static peers remain part of the stable identity/configuration;
        // directory-managed unpinned connector changes are applied in process.
        if let Some(toml::Value::Array(peers)) = stable_table.get_mut("peer") {
            peers.retain(|p| p.get("peer_public_key").is_some());
            if peers.is_empty() {
                stable_table.remove("peer");
            }
        }
        let peer_urls: std::collections::BTreeSet<_> = cfg
            .get_peers()
            .into_iter()
            .map(|v| v.uri.to_string())
            .collect();
        let lifetime = (reply.expires_at - now()?).clamp(0, MAX_LEASE) as u64;
        ensure!(lifetime > 0, "lease expired while preparing configuration");
        *self.active.lock().await = Some(ActiveLease {
            id: self.identity.instance_id,
            deadline: Instant::now() + Duration::from_secs(lifetime),
        });
        let result = tokio::time::timeout(Duration::from_secs(lifetime.min(5)), async {
            if let Some(instance) = self.manager.instance(self.identity.instance_id) {
                if self.stable_config.as_ref() == Some(&stable) {
                    use easytier_proto::api::{
                        config::{AclPatch, InstanceConfigPatch, UrlPatch},
                        manage::ManagedCredentialSet,
                    };
                    let generated = easytier_core::config::api::network_config_from_toml(&cfg);
                    let mut connectors = Vec::new();
                    for uri in peer_urls.difference(&self.peer_urls) {
                        connectors.push(UrlPatch {
                            action: 0,
                            url: Some(url::Url::parse(uri)?.into()),
                        });
                    }
                    for uri in self.peer_urls.difference(&peer_urls) {
                        connectors.push(UrlPatch {
                            action: 1,
                            url: Some(url::Url::parse(uri)?.into()),
                        });
                    }
                    easytier_core::management::apply_config_patch(
                        &instance,
                        InstanceConfigPatch {
                            connectors,
                            acl: Some(AclPatch {
                                acl: cfg.get_acl(),
                                ..Default::default()
                            }),
                            managed_credentials: Some(ManagedCredentialSet {
                                entries: generated.managed_credentials,
                            }),
                            ..Default::default()
                        },
                        None,
                    )
                    .await?;
                } else {
                    self.manager
                        .delete_network_instances([self.identity.instance_id])
                        .await?;
                    self.manager
                        .run_network_instance(cfg, ConfigFileControl::STATIC_CONFIG)?;
                }
            } else {
                self.manager
                    .run_network_instance(cfg, ConfigFileControl::STATIC_CONFIG)?;
            }
            let instance = self
                .manager
                .instance(self.identity.instance_id)
                .context("native instance disappeared during apply")?;
            loop {
                use easytier_core::instance::CoreInstanceState;
                match instance.state() {
                    CoreInstanceState::Running => break,
                    CoreInstanceState::Stopping | CoreInstanceState::Stopped => {
                        anyhow::bail!("native managed instance failed to start")
                    }
                    _ => tokio::time::sleep(Duration::from_millis(10)).await,
                }
            }
            anyhow::Ok(())
        })
        .await
        .context("managed native apply exceeded its bounded lease window")
        .and_then(|v| v);
        if let Err(error) = result {
            drop(guard);
            self.stop("configuration_error").await?;
            return Err(error);
        }
        self.stable_config = Some(stable);
        self.peer_urls = peer_urls;
        persist(
            &self.options.state_dir.join("directory.json"),
            &reply.directory,
        )?;
        persist(
            &self.options.state_dir.join("status.json"),
            &json!({"state":"approved","device_id":self.identity.device_id,"instance_id":self.identity.instance_id,"expires_at":reply.expires_at,"auth_revision":reply.auth_revision,"config_revision":reply.config_revision,"lease_id":reply.lease_id}),
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests;
