use pumpkin_data::packet::CURRENT_MC_PROTOCOL;
use pumpkin_data::packet::clientbound::CONFIG_DISCONNECT;
use pumpkin_protocol::codec::var_int::VarInt;
use pumpkin_protocol::java::server::handshake::SHandShake;
use pumpkin_protocol::java::server::login::SLoginStart;
use pumpkin_protocol::ser::NetworkWriteExt;
use pumpkin_protocol::{ConnectionState, ServerPacket};
use rsa::{Pkcs1v15Encrypt, RsaPrivateKey};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex as StdMutex, RwLock};
use std::time::{Duration, Instant};
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, watch};
use uuid::Uuid;

use crate::auth::{self, GameProfile};
use crate::backend::BackendConnection;
use crate::client::ClientConnection;
use crate::config::GourdConfig;
use crate::session::PlayerSession;

/// Maximum allowed packet size (2 MB) to prevent memory exhaustion attacks.
const MAX_PACKET_SIZE: usize = 2_097_152;

#[derive(Error, Debug)]
pub enum ProxyError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Packet encode error: {0}")]
    Encode(#[from] pumpkin_protocol::PacketEncodeError),
    #[error("Packet decode error: {0}")]
    Decode(#[from] pumpkin_protocol::PacketDecodeError),
    #[error("Reading error: {0}")]
    Reading(#[from] pumpkin_protocol::ser::ReadingError),
    #[error("Backend error: {0}")]
    Backend(#[from] crate::backend::BackendError),
    #[error("Auth error: {0}")]
    Auth(#[from] auth::AuthError),
    #[error("RSA error: {0}")]
    Rsa(#[from] rsa::Error),
    #[error("{0}")]
    Other(String),
}

struct LoginRateLimiter {
    attempts: StdMutex<HashMap<IpAddr, Vec<Instant>>>,
}

impl LoginRateLimiter {
    fn new() -> Self {
        Self {
            attempts: StdMutex::new(HashMap::new()),
        }
    }

    fn check(&self, ip: IpAddr, max_per_minute: u32) -> bool {
        let mut map = self.attempts.lock().unwrap();
        let now = Instant::now();
        let window = Duration::from_secs(60);

        let attempts = map.entry(ip).or_default();
        attempts.retain(|t| now.duration_since(*t) < window);

        if attempts.len() as u32 >= max_per_minute {
            return false;
        }
        attempts.push(now);
        true
    }
}

pub struct ProxyServer {
    config: RwLock<Arc<GourdConfig>>,
    pub rsa_key: Arc<RsaPrivateKey>,
    pub der_public_key: Arc<Vec<u8>>,
    player_count: AtomicU32,
    shutdown: watch::Sender<bool>,
    server_health: RwLock<HashMap<String, bool>>,
    sessions: RwLock<HashMap<String, (String, mpsc::Sender<String>)>>,
    login_rate_limiter: LoginRateLimiter,
}

impl ProxyServer {
    pub fn new(
        config: GourdConfig,
        rsa_key: Arc<RsaPrivateKey>,
        der_public_key: Arc<Vec<u8>>,
        shutdown: watch::Sender<bool>,
    ) -> Self {
        Self {
            config: RwLock::new(Arc::new(config)),
            rsa_key,
            der_public_key,
            player_count: AtomicU32::new(0),
            shutdown,
            server_health: RwLock::new(HashMap::new()),
            sessions: RwLock::new(HashMap::new()),
            login_rate_limiter: LoginRateLimiter::new(),
        }
    }

    pub fn config(&self) -> Arc<GourdConfig> {
        self.config.read().unwrap().clone()
    }

    pub fn reload_config(&self, new_config: GourdConfig) {
        *self.config.write().unwrap() = Arc::new(new_config);
    }

    pub fn player_count(&self) -> u32 {
        self.player_count.load(Ordering::Relaxed)
    }

    pub fn increment_players(&self) {
        self.player_count.fetch_add(1, Ordering::Relaxed);
    }

    pub fn decrement_players(&self) {
        self.player_count.fetch_sub(1, Ordering::Relaxed);
    }

    pub fn shutdown_receiver(&self) -> watch::Receiver<bool> {
        self.shutdown.subscribe()
    }

    pub fn update_server_health(&self, health: HashMap<String, bool>) {
        *self.server_health.write().unwrap() = health;
    }

    pub fn is_server_healthy(&self, name: &str) -> bool {
        self.server_health
            .read()
            .unwrap()
            .get(name)
            .copied()
            .unwrap_or(true)
    }

    pub fn register_session(&self, name: &str) -> mpsc::Receiver<String> {
        let (tx, rx) = mpsc::channel(4);
        self.sessions
            .write()
            .unwrap()
            .insert(name.to_lowercase(), (name.to_string(), tx));
        rx
    }

    pub fn unregister_session(&self, name: &str) {
        self.sessions.write().unwrap().remove(&name.to_lowercase());
    }

    pub fn send_player_to_server(&self, player: &str, server: &str) -> Result<(), String> {
        let sessions = self.sessions.read().unwrap();
        let (_, tx) = sessions
            .get(&player.to_lowercase())
            .ok_or_else(|| format!("Player '{}' not found", player))?;
        tx.try_send(server.to_string())
            .map_err(|_| format!("Failed to send transfer to '{}'", player))
    }

    pub fn online_player_names(&self) -> Vec<String> {
        self.sessions
            .read()
            .unwrap()
            .values()
            .map(|(display, _)| display.clone())
            .collect()
    }

    pub async fn handle_connection(
        self: &Arc<Self>,
        mut stream: TcpStream,
        addr: SocketAddr,
    ) -> Result<(), ProxyError> {
        stream.set_nodelay(true)?;

        let config = self.config();
        let timeout_dur = Duration::from_secs(config.login_timeout_secs);

        let hs_len = validated_packet_length(raw_read_varint(&mut stream).await?)?;
        let mut hs_buf = vec![0u8; hs_len];
        stream.read_exact(&mut hs_buf).await?;

        let mut hs_off = 0;
        skip_varint(&hs_buf, &mut hs_off);
        let handshake = SHandShake::read(&hs_buf[hs_off..])?;

        log::debug!(
            "Handshake from {}: protocol={}, next_state={:?}",
            addr,
            handshake.protocol_version.0,
            handshake.next_state
        );

        match handshake.next_state {
            ConnectionState::Status => {
                tokio::time::timeout(Duration::from_secs(5), self.handle_status_raw(&mut stream))
                    .await
                    .map_err(|_| ProxyError::Other("Status request timed out".to_string()))??;
            }
            ConnectionState::Login => {
                if !self
                    .login_rate_limiter
                    .check(addr.ip(), config.login_rate_limit)
                {
                    log::warn!("Login rate limit exceeded for {}", addr.ip());
                    return Ok(());
                }

                let (profile, client, backend, server_name) =
                    tokio::time::timeout(timeout_dur, self.perform_login(stream, addr))
                        .await
                        .map_err(|_| {
                            log::warn!("Login from {} timed out", addr);
                            ProxyError::Other("Login timed out".to_string())
                        })??;

                self.increment_players();
                let shutdown_rx = self.shutdown_receiver();
                let transfer_rx = self.register_session(&profile.name);
                let session = Arc::new(PlayerSession::new(
                    client,
                    profile,
                    self.clone(),
                    shutdown_rx,
                    transfer_rx,
                ));
                session.run(backend, server_name).await;
                self.decrement_players();
            }
            _ => {
                log::warn!("Unexpected next_state in handshake from {}", addr);
            }
        }

        Ok(())
    }

    async fn handle_status_raw(&self, stream: &mut TcpStream) -> Result<(), ProxyError> {
        let sr_len = validated_packet_length(raw_read_varint(stream).await?)?;
        let mut sr_buf = vec![0u8; sr_len];
        stream.read_exact(&mut sr_buf).await?;

        let config = self.config();
        let status_json = serde_json::json!({
            "version": {
                "name": "1.21.11",
                "protocol": CURRENT_MC_PROTOCOL,
            },
            "players": {
                "max": config.max_players,
                "online": self.player_count(),
                "sample": [],
            },
            "description": parse_motd(&config.motd),
        });

        let json_str = status_json.to_string();
        let mut payload = Vec::new();
        payload.extend_from_slice(&encode_varint(0x00)); // StatusResponse
        payload.extend_from_slice(&encode_varint(json_str.len() as i32));
        payload.extend_from_slice(json_str.as_bytes());
        raw_write_framed(stream, &payload).await?;

        match raw_read_varint(stream).await {
            Ok(ping_len) => {
                let ping_len = validated_packet_length(ping_len)?;
                let mut ping_buf = vec![0u8; ping_len];
                stream.read_exact(&mut ping_buf).await?;

                let mut pong = Vec::new();
                pong.extend_from_slice(&encode_varint(0x01)); // PingResponse
                pong.extend_from_slice(&ping_buf[1..]);
                raw_write_framed(stream, &pong).await?;
            }
            Err(_) => {
                log::debug!("Client disconnected before ping (normal for server list)");
            }
        }

        Ok(())
    }

    /// Perform the login handshake and connect to the backend.
    /// Separated so the login phase can be wrapped in a timeout.
    async fn perform_login(
        &self,
        mut stream: TcpStream,
        addr: SocketAddr,
    ) -> Result<
        (
            GameProfile,
            Arc<ClientConnection>,
            BackendConnection,
            String,
        ),
        ProxyError,
    > {
        let config = self.config();

        let ls_len = validated_packet_length(raw_read_varint(&mut stream).await?)?;
        let mut ls_buf = vec![0u8; ls_len];
        stream.read_exact(&mut ls_buf).await?;

        let mut off = 0;
        skip_varint(&ls_buf, &mut off);
        let login_start = SLoginStart::read(&ls_buf[off..])?;
        let login_name = login_start.name.clone();
        validate_username(&login_name)?;

        if config
            .blacklist
            .iter()
            .any(|b| b.eq_ignore_ascii_case(&login_name))
        {
            send_login_disconnect(&mut stream, "You are banned from this server").await?;
            return Err(ProxyError::Other(format!(
                "Player '{}' is blacklisted",
                login_name
            )));
        }

        if config.whitelist_enabled
            && !config
                .whitelist
                .iter()
                .any(|w| w.eq_ignore_ascii_case(&login_name))
        {
            send_login_disconnect(&mut stream, "You are not whitelisted on this server").await?;
            return Err(ProxyError::Other(format!(
                "Player '{}' is not whitelisted",
                login_name
            )));
        }

        log::info!("Login from {} ({})", login_name, addr);

        let (profile, client) = if config.online_mode {
            self.handle_online_login(stream, addr, &login_name).await?
        } else {
            self.handle_offline_login(stream, addr, &login_name).await?
        };

        log::debug!(
            "[{}] Login complete, connecting to backend...",
            profile.name
        );

        // Try default server first, then fall back to others
        let mut server_order = vec![config.default_server.clone()];
        for name in config.servers.keys() {
            if *name != config.default_server {
                server_order.push(name.clone());
            }
        }

        let mut last_err = None;
        for server_name in &server_order {
            let server = match config.servers.get(server_name) {
                Some(s) => s,
                None => continue,
            };
            let backend_addr: SocketAddr = match server.address.parse() {
                Ok(a) => a,
                Err(e) => {
                    log::warn!(
                        "[{}] Invalid address for '{}': {}",
                        profile.name,
                        server_name,
                        e
                    );
                    continue;
                }
            };
            match BackendConnection::connect(
                backend_addr,
                &profile.name,
                profile.id,
                &profile,
                &config.gourd_secret,
                &client.address,
            )
            .await
            {
                Ok(backend) => {
                    if *server_name != config.default_server {
                        log::info!(
                            "[{}] Default server '{}' unavailable, connected to '{}'",
                            profile.name,
                            config.default_server,
                            server_name
                        );
                    } else {
                        log::info!(
                            "[{}] Connected to backend '{}' ({})",
                            profile.name,
                            server_name,
                            backend_addr
                        );
                    }
                    return Ok((profile, client, backend, server_name.clone()));
                }
                Err(e) => {
                    log::warn!(
                        "[{}] Failed to connect to '{}': {}",
                        profile.name,
                        server_name,
                        e
                    );
                    last_err = Some(e);
                }
            }
        }

        let _ = client
            .send_raw_bytes(build_config_disconnect("\u{00a7}cNo backend servers available").into())
            .await;

        Err(ProxyError::Other(format!(
            "All backend servers unavailable: {}",
            last_err.map_or("none configured".to_string(), |e| e.to_string())
        )))
    }

    /// Online mode: encryption handshake via raw TCP, then Mojang auth,
    /// compression, and LoginSuccess through the encrypted ClientConnection.
    async fn handle_online_login(
        &self,
        mut stream: TcpStream,
        addr: SocketAddr,
        login_name: &str,
    ) -> Result<(GameProfile, Arc<ClientConnection>), ProxyError> {
        let verify_token: [u8; 4] = rand::random();
        log::debug!(
            "[{}] Sending encryption request (pubkey={} bytes)",
            login_name,
            self.der_public_key.len()
        );
        let mut enc_req = Vec::new();
        enc_req.extend_from_slice(&encode_varint(0x01)); // EncryptionRequest
        enc_req.extend_from_slice(&encode_varint(0)); // empty server_id
        enc_req.extend_from_slice(&encode_varint(self.der_public_key.len() as i32));
        enc_req.extend_from_slice(&self.der_public_key);
        enc_req.extend_from_slice(&encode_varint(verify_token.len() as i32));
        enc_req.extend_from_slice(&verify_token);
        enc_req.push(0x01); // should_authenticate
        raw_write_framed(&mut stream, &enc_req).await?;

        log::debug!("[{}] Waiting for encryption response...", login_name);
        let er_len = validated_packet_length(raw_read_varint(&mut stream).await?)?;
        let mut er_buf = vec![0u8; er_len];
        stream.read_exact(&mut er_buf).await?;

        let mut off = 0;
        skip_varint(&er_buf, &mut off);
        let enc_response =
            pumpkin_protocol::java::server::login::SEncryptionResponse::read(&er_buf[off..])?;
        log::debug!("[{}] Got encryption response", login_name);

        let shared_secret = self
            .rsa_key
            .decrypt(Pkcs1v15Encrypt, &enc_response.shared_secret)?;
        let decrypted_token = self
            .rsa_key
            .decrypt(Pkcs1v15Encrypt, &enc_response.verify_token)?;

        if decrypted_token != verify_token {
            return Err(ProxyError::Other("Verify token mismatch".to_string()));
        }

        let key: [u8; 16] = shared_secret
            .clone()
            .try_into()
            .map_err(|_| ProxyError::Other("Shared secret wrong length".to_string()))?;

        // From this point on, all I/O goes through the encrypted ClientConnection.
        let client = Arc::new(ClientConnection::new(stream, addr));
        client.set_encryption(&key).await;
        log::debug!("[{}] Encryption enabled", login_name);

        let server_hash = auth::server_hash("", &shared_secret, &self.der_public_key);
        let name_clone = login_name.to_string();
        let profile = tokio::time::timeout(
            Duration::from_secs(10),
            tokio::task::spawn_blocking(move || auth::authenticate(&name_clone, &server_hash)),
        )
        .await
        .map_err(|_| ProxyError::Other("Mojang authentication timed out".to_string()))?
        .map_err(|e| ProxyError::Other(format!("Auth task failed: {}", e)))??;

        log::info!("[{}] Authenticated (UUID: {})", profile.name, profile.id);

        let config = self.config();
        let threshold = config.compression_threshold;
        if threshold >= 0 {
            let mut set_comp = Vec::new();
            set_comp.write_var_int(&VarInt(0x03)).unwrap(); // SetCompression
            set_comp.write_var_int(&VarInt(threshold)).unwrap();
            client
                .send_raw_bytes(set_comp.into())
                .await
                .map_err(ProxyError::Encode)?;
            client.set_compression(threshold as usize, 6).await;
            log::debug!(
                "[{}] SetCompression sent (threshold={})",
                profile.name,
                threshold
            );
        }

        let login_success = build_login_success_payload(&profile);
        client
            .send_raw_bytes(login_success.into())
            .await
            .map_err(ProxyError::Encode)?;
        log::debug!("[{}] LoginSuccess sent", profile.name);

        let ack = client.read_raw_packet().await.map_err(ProxyError::Decode)?;
        log::debug!(
            "[{}] Login acknowledged (packet id=0x{:02X})",
            profile.name,
            ack.id
        );

        client.connection_state.store(ConnectionState::Config);

        Ok((profile, client))
    }

    /// Offline mode: compression + LoginSuccess via raw TCP, then wrap in ClientConnection.
    async fn handle_offline_login(
        &self,
        mut stream: TcpStream,
        addr: SocketAddr,
        login_name: &str,
    ) -> Result<(GameProfile, Arc<ClientConnection>), ProxyError> {
        let config = self.config();
        let threshold = config.compression_threshold;

        if threshold >= 0 {
            let mut set_comp = Vec::new();
            set_comp.extend_from_slice(&encode_varint(0x03)); // SetCompression
            set_comp.extend_from_slice(&encode_varint(threshold));
            raw_write_framed(&mut stream, &set_comp).await?;
            log::debug!(
                "[{}] SetCompression sent (threshold={})",
                login_name,
                threshold
            );
        }

        let offline_uuid = Uuid::new_v3(
            &Uuid::NAMESPACE_URL,
            format!("OfflinePlayer:{}", login_name).as_bytes(),
        );
        let profile = GameProfile {
            id: offline_uuid,
            name: login_name.to_string(),
            properties: vec![],
        };

        let login_success = build_login_success_payload(&profile);
        if threshold >= 0 {
            raw_write_compressed_framed(&mut stream, &login_success, threshold as usize).await?;
        } else {
            raw_write_framed(&mut stream, &login_success).await?;
        }
        log::debug!("[{}] LoginSuccess sent", profile.name);

        log::debug!("[{}] Waiting for login acknowledged...", login_name);
        let ack = if threshold >= 0 {
            raw_read_compressed_packet(&mut stream).await?
        } else {
            let len = validated_packet_length(raw_read_varint(&mut stream).await?)?;
            let mut buf = vec![0u8; len];
            stream.read_exact(&mut buf).await?;
            buf
        };
        log::debug!(
            "[{}] Login acknowledged ({} bytes)",
            profile.name,
            ack.len()
        );

        let compression = if threshold >= 0 {
            Some((threshold as usize, 6u32))
        } else {
            None
        };
        let client = Arc::new(ClientConnection::new_post_login(stream, addr, compression));

        Ok((profile, client))
    }
}

fn build_login_success_payload(profile: &GameProfile) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.write_var_int(&VarInt(0x02)).unwrap(); // LoginSuccess
    buf.extend_from_slice(profile.id.as_bytes());
    buf.write_string(&profile.name).unwrap();
    buf.write_var_int(&VarInt(profile.properties.len() as i32))
        .unwrap();
    for prop in &profile.properties {
        buf.write_string(&prop.name).unwrap();
        buf.write_string(&prop.value).unwrap();
        buf.write_option(&prop.signature, |w, sig| w.write_string(sig))
            .unwrap();
    }
    buf
}

/// Validate a Minecraft username (3-16 chars, alphanumeric + underscore).
fn validate_username(name: &str) -> Result<(), ProxyError> {
    if name.len() < 3 || name.len() > 16 {
        return Err(ProxyError::Other(format!(
            "Invalid username length: {}",
            name.len()
        )));
    }
    if !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return Err(ProxyError::Other("Invalid username characters".to_string()));
    }
    Ok(())
}

fn validated_packet_length(raw_len: i32) -> Result<usize, ProxyError> {
    if raw_len < 0 || raw_len as usize > MAX_PACKET_SIZE {
        return Err(ProxyError::Other(format!(
            "Invalid packet length: {}",
            raw_len
        )));
    }
    Ok(raw_len as usize)
}

async fn raw_read_varint(stream: &mut TcpStream) -> Result<i32, ProxyError> {
    let mut val: i32 = 0;
    for i in 0..5 {
        let byte = stream.read_u8().await?;
        val |= (i32::from(byte) & 0x7F) << (i * 7);
        if byte & 0x80 == 0 {
            return Ok(val);
        }
    }
    Err(ProxyError::Other("VarInt too large".to_string()))
}

fn encode_varint(val: i32) -> Vec<u8> {
    let mut v = val as u32;
    let mut buf = Vec::new();
    loop {
        let mut byte = (v & 0x7F) as u8;
        v >>= 7;
        if v != 0 {
            byte |= 0x80;
        }
        buf.push(byte);
        if v == 0 {
            break;
        }
    }
    buf
}

fn skip_varint(data: &[u8], offset: &mut usize) {
    for _ in 0..5 {
        if *offset >= data.len() {
            break;
        }
        let byte = data[*offset];
        *offset += 1;
        if byte & 0x80 == 0 {
            break;
        }
    }
}

/// Build a Config Disconnect packet with NBT-encoded text component.
/// MC 1.20.3+ uses NBT (not JSON) for text components in config packets.
fn build_config_disconnect(reason: &str) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.write_var_int(&VarInt(CONFIG_DISCONNECT.latest_id))
        .unwrap();
    // NBT String Tag (network format: type byte + string data, no name)
    buf.push(0x08); // TAG_String
    let bytes = reason.as_bytes();
    buf.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
    buf.extend_from_slice(bytes);
    buf
}

async fn send_login_disconnect(stream: &mut TcpStream, reason: &str) -> Result<(), ProxyError> {
    let json = serde_json::json!({"text": reason}).to_string();
    let mut payload = Vec::new();
    payload.extend_from_slice(&encode_varint(0x00)); // LoginDisconnect
    payload.extend_from_slice(&encode_varint(json.len() as i32));
    payload.extend_from_slice(json.as_bytes());
    raw_write_framed(stream, &payload).await
}

async fn raw_write_framed(stream: &mut TcpStream, payload: &[u8]) -> Result<(), ProxyError> {
    let len_bytes = encode_varint(payload.len() as i32);
    stream.write_all(&len_bytes).await?;
    stream.write_all(payload).await?;
    stream.flush().await?;
    Ok(())
}

/// Write with compression framing: data_length=0 (uncompressed) + payload.
async fn raw_write_compressed_framed(
    stream: &mut TcpStream,
    payload: &[u8],
    _threshold: usize,
) -> Result<(), ProxyError> {
    let data_length_bytes = encode_varint(0);
    let packet_length = data_length_bytes.len() + payload.len();
    let packet_length_bytes = encode_varint(packet_length as i32);

    stream.write_all(&packet_length_bytes).await?;
    stream.write_all(&data_length_bytes).await?;
    stream.write_all(payload).await?;
    stream.flush().await?;
    Ok(())
}

async fn raw_read_compressed_packet(stream: &mut TcpStream) -> Result<Vec<u8>, ProxyError> {
    let packet_length = validated_packet_length(raw_read_varint(stream).await?)?;
    let mut packet_buf = vec![0u8; packet_length];
    stream.read_exact(&mut packet_buf).await?;

    let mut cursor = &packet_buf[..];
    let data_length = VarInt::decode(&mut cursor)
        .map_err(|_| ProxyError::Other("Failed to read data_length VarInt".to_string()))?;

    if data_length.0 == 0 {
        Ok(cursor.to_vec())
    } else {
        Err(ProxyError::Other(
            "Compressed LoginAcknowledged not expected".to_string(),
        ))
    }
}

/// Parse a MOTD string with `&` color/formatting codes into a JSON text component.
/// Supports `&0`-`&9`, `&a`-`&f` (colors), `&l` (bold), `&m` (strikethrough),
/// `&n` (underline), `&o` (italic), `&r` (reset), and `\n` for newlines.
fn parse_motd(motd: &str) -> serde_json::Value {
    if !motd.contains('&') {
        return serde_json::json!({"text": motd});
    }

    let mut parts: Vec<serde_json::Value> = Vec::new();
    let mut current_text = String::new();
    let mut color: Option<&str> = None;
    let mut bold = false;
    let mut italic = false;
    let mut underlined = false;
    let mut strikethrough = false;

    let flush_part = |text: &mut String,
                      color: Option<&str>,
                      bold,
                      italic,
                      underlined,
                      strikethrough,
                      parts: &mut Vec<serde_json::Value>| {
        if text.is_empty() {
            return;
        }
        let mut part = serde_json::json!({"text": *text});
        if let Some(c) = color {
            part["color"] = c.into();
        }
        if bold {
            part["bold"] = true.into();
        }
        if italic {
            part["italic"] = true.into();
        }
        if underlined {
            part["underlined"] = true.into();
        }
        if strikethrough {
            part["strikethrough"] = true.into();
        }
        parts.push(part);
        *text = String::new();
    };

    let mut chars = motd.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '&'
            && let Some(&code) = chars.peek()
        {
            let mapped_color = match code {
                '0' => Some("black"),
                '1' => Some("dark_blue"),
                '2' => Some("dark_green"),
                '3' => Some("dark_aqua"),
                '4' => Some("dark_red"),
                '5' => Some("dark_purple"),
                '6' => Some("gold"),
                '7' => Some("gray"),
                '8' => Some("dark_gray"),
                '9' => Some("blue"),
                'a' => Some("green"),
                'b' => Some("aqua"),
                'c' => Some("red"),
                'd' => Some("light_purple"),
                'e' => Some("yellow"),
                'f' => Some("white"),
                _ => None,
            };
            let is_format = matches!(code, 'l' | 'm' | 'n' | 'o' | 'r');

            if mapped_color.is_some() || is_format {
                chars.next();
                flush_part(
                    &mut current_text,
                    color,
                    bold,
                    italic,
                    underlined,
                    strikethrough,
                    &mut parts,
                );

                if code == 'r' {
                    color = None;
                    bold = false;
                    italic = false;
                    underlined = false;
                    strikethrough = false;
                } else if let Some(c) = mapped_color {
                    color = Some(c);
                } else {
                    match code {
                        'l' => bold = true,
                        'm' => strikethrough = true,
                        'n' => underlined = true,
                        'o' => italic = true,
                        _ => {}
                    }
                }
                continue;
            }
        }
        current_text.push(ch);
    }

    flush_part(
        &mut current_text,
        color,
        bold,
        italic,
        underlined,
        strikethrough,
        &mut parts,
    );
    if parts.is_empty() {
        parts.push(serde_json::json!({"text": ""}));
    }

    if parts.len() == 1 {
        parts.remove(0)
    } else {
        let first = parts.remove(0);
        let mut result = first;
        result["extra"] = serde_json::Value::Array(parts);
        result
    }
}
