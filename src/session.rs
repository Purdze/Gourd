use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use pumpkin_data::packet::clientbound::{
    CONFIG_FINISH_CONFIGURATION as CB_FINISH_CONFIG, PLAY_CUSTOM_PAYLOAD, PLAY_START_CONFIGURATION,
};
use pumpkin_data::packet::serverbound::{
    CONFIG_FINISH_CONFIGURATION as SB_FINISH_CONFIG, PLAY_CHAT_COMMAND, PLAY_COMMAND_SUGGESTION,
};
use pumpkin_protocol::codec::var_int::VarInt;
use pumpkin_protocol::java::client::play::{
    CCommandSuggestions, CPlayDisconnect, CSystemChatMessage, CommandSuggestion,
};
use pumpkin_protocol::java::server::play::{SChatCommand, SCommandSuggestion};
use pumpkin_protocol::ser::NetworkWriteExt;
use pumpkin_protocol::{PacketDecodeError, ServerPacket};
use pumpkin_util::text::TextComponent;
use tokio::sync::{Mutex, mpsc, watch};

use crate::auth::GameProfile;
use crate::backend::BackendConnection;
use crate::client::ClientConnection;
use crate::proxy::{ProxyError, ProxyServer};

enum RelayResult {
    ClientDisconnected,
    BackendDisconnected,
    SwitchServer(String),
}

/// Bridges a client and backend connection, relaying packets
/// and handling `/server` and `/send` commands.
pub struct PlayerSession {
    pub client: Arc<ClientConnection>,
    pub profile: GameProfile,
    proxy: Arc<ProxyServer>,
    shutdown: watch::Receiver<bool>,
    transfer_rx: Mutex<mpsc::Receiver<String>>,
}

impl PlayerSession {
    pub fn new(
        client: Arc<ClientConnection>,
        profile: GameProfile,
        proxy: Arc<ProxyServer>,
        shutdown: watch::Receiver<bool>,
        transfer_rx: mpsc::Receiver<String>,
    ) -> Self {
        Self {
            client,
            profile,
            proxy,
            shutdown,
            transfer_rx: Mutex::new(transfer_rx),
        }
    }

    pub async fn run(self: Arc<Self>, initial_backend: BackendConnection, initial_server: String) {
        let mut backend = Arc::new(initial_backend);
        let mut current_server = initial_server;

        loop {
            match self.relay_packets(&backend, &current_server).await {
                RelayResult::ClientDisconnected => break,
                RelayResult::BackendDisconnected => {
                    let config = self.proxy.config();
                    let fallback = config.fallback_server.as_deref().filter(|fb| {
                        *fb != current_server
                            && config.servers.contains_key(*fb)
                            && self.proxy.is_server_healthy(fb)
                    });
                    if let Some(fb) = fallback {
                        let fb_name = fb.to_string();
                        log::info!(
                            "[{}] Backend '{}' lost, falling back to '{}'",
                            self.profile.name,
                            current_server,
                            fb_name
                        );
                        let _ = self
                            .send_system_chat(&format!(
                                "\u{00a7}eBackend server lost. Sending you to \u{00a7}a{}\u{00a7}e...",
                                fb_name
                            ))
                            .await;
                        match self.switch_server(&fb_name).await {
                            Ok(new_backend) => {
                                backend = Arc::new(new_backend);
                                current_server = fb_name;
                                continue;
                            }
                            Err(e) => {
                                log::error!(
                                    "[{}] Fallback to '{}' failed: {}",
                                    self.profile.name,
                                    fb_name,
                                    e
                                );
                            }
                        }
                    }
                    let _ = self.send_disconnect("Backend server connection lost").await;
                    break;
                }
                RelayResult::SwitchServer(name) => {
                    if name == current_server {
                        let _ = self
                            .send_system_chat(&format!(
                                "\u{00a7}cYou are already on \u{00a7}e{}",
                                name
                            ))
                            .await;
                        continue;
                    }
                    match self.switch_server(&name).await {
                        Ok(new_backend) => {
                            backend = Arc::new(new_backend);
                            current_server = name.clone();
                            log::info!("[{}] Now playing on '{}'", self.profile.name, name);
                        }
                        Err(e) => {
                            log::error!(
                                "[{}] Server switch to '{}' failed: {}",
                                self.profile.name,
                                name,
                                e
                            );
                            let _ = self
                                .send_system_chat(&format!("\u{00a7}cFailed to switch: {}", e))
                                .await;
                        }
                    }
                }
            }
        }

        self.proxy.unregister_session(&self.profile.name);
        log::info!("Session ended for {}", self.profile.name);
    }

    async fn relay_packets(
        &self,
        backend: &BackendConnection,
        current_server: &str,
    ) -> RelayResult {
        let mut shutdown = self.shutdown.clone();
        let idle_timeout = Duration::from_secs(self.proxy.config().idle_timeout_secs);
        let mut pkt_count: u64 = 0;
        let mut recent_backend_ids: Vec<(i32, usize)> = Vec::new();

        // CANCELLATION SAFETY: read futures persist across select! iterations.
        // TCPNetworkDecoder::get_raw_packet() is NOT cancel-safe — dropping it
        // mid-read leaves the TCP stream at an arbitrary position inside a
        // packet, corrupting all subsequent reads. By keeping the futures alive
        // with Box::pin + &mut, a cancelled branch resumes where it left off
        // instead of being dropped and restarted.
        let mut client_read = Box::pin(self.client.read_raw_packet());
        let mut backend_read = Box::pin(backend.read_raw_packet());

        loop {
            let packet_result = tokio::time::timeout(idle_timeout, async {
                let mut transfer_rx = self.transfer_rx.lock().await;
                tokio::select! {
                    result = &mut client_read => {
                        client_read = Box::pin(self.client.read_raw_packet());
                        match result {
                            Ok(raw) => {
                                if raw.id == PLAY_CHAT_COMMAND.latest_id
                                    && let Ok(cmd) = SChatCommand::read(&raw.payload[..])
                                {
                                    if let Some(server_name) = cmd.command.strip_prefix("server ") {
                                        return Some(RelayResult::SwitchServer(
                                            server_name.trim().to_string(),
                                        ));
                                    }
                                    if cmd.command.trim() == "server" {
                                        let _ = self.send_server_list().await;
                                        return None;
                                    }
                                    if cmd.command.starts_with("send") {
                                        let args = cmd.command.strip_prefix("send ").unwrap_or("");
                                        let _ = self.handle_send_command(args).await;
                                        return None;
                                    }
                                }

                                if raw.id == PLAY_COMMAND_SUGGESTION.latest_id
                                    && let Ok(req) = SCommandSuggestion::read(&raw.payload[..])
                                {
                                    if req.command.starts_with("/server ") {
                                        let _ = self.handle_server_tab_complete(&req).await;
                                        return None;
                                    }
                                    if req.command.starts_with("/send ") {
                                        let _ = self.handle_send_tab_complete(&req).await;
                                        return None;
                                    }
                                }

                                if let Err(e) = backend.forward_raw_packet(&raw).await {
                                    log::warn!(
                                        "[{}] Forward to backend failed (after {} B→C pkts, \
                                         last ids: {:?}): {}",
                                        self.profile.name, pkt_count,
                                        recent_backend_ids, e
                                    );
                                    return Some(RelayResult::BackendDisconnected);
                                }
                                None
                            }
                            Err(PacketDecodeError::ConnectionClosed) => {
                                log::info!("Client {} disconnected", self.profile.name);
                                Some(RelayResult::ClientDisconnected)
                            }
                            Err(e) => {
                                log::warn!(
                                    "Error reading from client {}: {}",
                                    self.profile.name, e
                                );
                                Some(RelayResult::ClientDisconnected)
                            }
                        }
                    }
                    result = &mut backend_read => {
                        backend_read = Box::pin(backend.read_raw_packet());
                        match result {
                            Ok(raw) => {
                                if raw.id == PLAY_CUSTOM_PAYLOAD.latest_id {
                                    log::debug!(
                                        "[{}] Got custom payload packet (id={}), payload={}B, first 32 bytes: {:02X?}",
                                        self.profile.name, raw.id, raw.payload.len(),
                                        &raw.payload[..raw.payload.len().min(32)]
                                    );
                                    match parse_gourd_transfer(&raw.payload) {
                                        Some(server_name) => {
                                            log::info!(
                                                "[{}] Backend requested transfer to '{}'",
                                                self.profile.name, server_name
                                            );
                                            return Some(RelayResult::SwitchServer(server_name));
                                        }
                                        None => {
                                            log::debug!(
                                                "[{}] Custom payload is not gourd:transfer, forwarding",
                                                self.profile.name
                                            );
                                        }
                                    }
                                }
                                if pkt_count < 20 {
                                    log::debug!(
                                        "[{}] B→C #{}: id={} (0x{:02X}) payload={}B",
                                        self.profile.name, pkt_count, raw.id, raw.id,
                                        raw.payload.len()
                                    );
                                }
                                if raw.id == 0 && !raw.payload.is_empty() {
                                    let mut probe = &raw.payload[..];
                                    let inner_id = pumpkin_protocol::codec::var_int::VarInt
                                        ::decode(&mut probe)
                                        .map(|v| v.0)
                                        .ok();
                                    log::warn!(
                                        "[{}] Forwarding packet id=0 with {} extra bytes \
                                         (bundle_delimiter should be empty). \
                                         Inner VarInt: {:?}, first 16 bytes: {:02X?}",
                                        self.profile.name,
                                        raw.payload.len(),
                                        inner_id,
                                        &raw.payload[..raw.payload.len().min(16)]
                                    );
                                }
                                if recent_backend_ids.len() >= 8 {
                                    recent_backend_ids.remove(0);
                                }
                                recent_backend_ids.push((raw.id, raw.payload.len()));
                                pkt_count += 1;
                                if let Err(e) = self.client.forward_raw_packet(&raw).await {
                                    log::warn!(
                                        "Error forwarding to client {}: {}",
                                        self.profile.name, e
                                    );
                                    return Some(RelayResult::ClientDisconnected);
                                }
                                None
                            }
                            Err(PacketDecodeError::ConnectionClosed) => {
                                log::warn!(
                                    "[{}] Backend '{}' closed connection \
                                     (after {} pkts, last ids: {:?})",
                                    self.profile.name, current_server,
                                    pkt_count, recent_backend_ids
                                );
                                Some(RelayResult::BackendDisconnected)
                            }
                            Err(e) => {
                                log::error!(
                                    "[{}] Backend '{}' read error: {:?} \
                                     (after {} pkts, last ids: {:?})",
                                    self.profile.name, current_server,
                                    e, pkt_count, recent_backend_ids
                                );
                                Some(RelayResult::BackendDisconnected)
                            }
                        }
                    }
                    server_name = transfer_rx.recv() => {
                        match server_name {
                            Some(name) if name != current_server => {
                                Some(RelayResult::SwitchServer(name))
                            }
                            _ => None,
                        }
                    }
                    _ = shutdown.changed() => {
                        let _ = self.send_disconnect("Proxy shutting down").await;
                        Some(RelayResult::ClientDisconnected)
                    }
                }
            })
            .await;

            match packet_result {
                Ok(Some(result)) => return result,
                Ok(None) => continue,
                Err(_) => {
                    log::warn!(
                        "Idle timeout for {} ({}s with no activity)",
                        self.profile.name,
                        idle_timeout.as_secs()
                    );
                    let _ = self.send_disconnect("Disconnected: idle timeout").await;
                    return RelayResult::ClientDisconnected;
                }
            }
        }
    }

    /// Switch the player to a different backend server by transitioning
    /// through Play -> Config, connecting to the new backend, relaying
    /// config packets, then returning to Play.
    async fn switch_server(&self, server_name: &str) -> Result<BackendConnection, ProxyError> {
        let config = self.proxy.config();
        let server = config
            .servers
            .get(server_name)
            .ok_or_else(|| ProxyError::Other(format!("Server '{}' not found", server_name)))?;

        self.send_system_chat(&format!(
            "\u{00a7}aSwitching to \u{00a7}e{}\u{00a7}a...",
            server_name
        ))
        .await?;

        self.send_start_configuration().await?;

        let ack = self
            .client
            .read_raw_packet()
            .await
            .map_err(ProxyError::Decode)?;
        log::debug!(
            "[{}] Client acknowledged configuration (packet id=0x{:02X})",
            self.profile.name,
            ack.id
        );

        let backend_addr: SocketAddr = server
            .address
            .parse()
            .map_err(|e| ProxyError::Other(format!("Invalid backend address: {}", e)))?;

        let backend = BackendConnection::connect(
            backend_addr,
            &self.profile.name,
            self.profile.id,
            &self.profile,
            &config.gourd_secret,
            &self.client.address,
        )
        .await?;

        log::info!(
            "[{}] Connected to new backend '{}' ({})",
            self.profile.name,
            server_name,
            backend_addr
        );

        self.relay_config_phase(&backend).await?;

        Ok(backend)
    }

    /// Relay config-phase packets until the FinishConfig exchange completes.
    async fn relay_config_phase(&self, backend: &BackendConnection) -> Result<(), ProxyError> {
        let mut finish_sent = false;

        // Cancellation-safe: persistent read futures (same rationale as relay_packets).
        let mut backend_read = Box::pin(backend.read_raw_packet());
        let mut client_read = Box::pin(self.client.read_raw_packet());

        loop {
            tokio::select! {
                result = &mut backend_read => {
                    backend_read = Box::pin(backend.read_raw_packet());
                    let raw = result.map_err(ProxyError::Decode)?;
                    let is_finish = raw.id == CB_FINISH_CONFIG.latest_id;
                    self.client.forward_raw_packet(&raw).await.map_err(ProxyError::Encode)?;
                    if is_finish {
                        finish_sent = true;
                    }
                }
                result = &mut client_read => {
                    client_read = Box::pin(self.client.read_raw_packet());
                    let raw = result.map_err(ProxyError::Decode)?;
                    let is_ack_finish = finish_sent && raw.id == SB_FINISH_CONFIG.latest_id;
                    backend.forward_raw_packet(&raw).await.map_err(ProxyError::Encode)?;
                    if is_ack_finish {
                        break;
                    }
                }
            }
        }

        Ok(())
    }

    async fn send_system_chat(&self, message: &str) -> Result<(), ProxyError> {
        let text = TextComponent::text(message.to_string());
        self.client
            .send_packet(&CSystemChatMessage::new(&text, false))
            .await
            .map_err(ProxyError::Encode)
    }

    async fn send_disconnect(&self, reason: &str) -> Result<(), ProxyError> {
        let text = TextComponent::text(reason.to_string());
        self.client
            .send_packet(&CPlayDisconnect::new(&text))
            .await
            .map_err(ProxyError::Encode)
    }

    async fn send_start_configuration(&self) -> Result<(), ProxyError> {
        let mut buf = Vec::new();
        buf.write_var_int(&VarInt(PLAY_START_CONFIGURATION.latest_id))
            .unwrap();
        self.client
            .send_raw_bytes(buf.into())
            .await
            .map_err(ProxyError::Encode)
    }

    async fn send_server_list(&self) -> Result<(), ProxyError> {
        let config = self.proxy.config();
        let mut entries: Vec<(&String, &crate::config::ServerEntry)> =
            config.servers.iter().collect();
        entries.sort_by_key(|(name, _)| name.as_str());
        let list = entries
            .iter()
            .map(|(name, entry)| {
                let health = if self.proxy.is_server_healthy(name) {
                    "\u{00a7}a\u{2714}"
                } else {
                    "\u{00a7}c\u{2718}"
                };
                format!(
                    "{} \u{00a7}a{} \u{00a7}7- \u{00a7}f{}",
                    health, name, entry.motd
                )
            })
            .collect::<Vec<_>>()
            .join("\n");
        let msg = format!("\u{00a7}eAvailable servers:\n{}", list);
        self.send_system_chat(&msg).await
    }

    async fn handle_server_tab_complete(&self, req: &SCommandSuggestion) -> Result<(), ProxyError> {
        let partial = &req.command["/server ".len()..];
        let matches = self.server_name_suggestions(partial);
        self.send_suggestions(
            req.id,
            "/server ".len() as i32,
            partial.len() as i32,
            matches,
        )
        .await
    }

    async fn handle_send_command(&self, args: &str) -> Result<(), ProxyError> {
        let parts: Vec<&str> = args.trim().splitn(2, ' ').collect();
        if parts.len() < 2 || parts[0].is_empty() {
            return self
                .send_system_chat("\u{00a7}cUsage: /send <player> <server>")
                .await;
        }
        let target_name = parts[0];
        let server_name = parts[1].trim();

        let config = self.proxy.config();
        if !config.servers.contains_key(server_name) {
            return self
                .send_system_chat(&format!(
                    "\u{00a7}cServer '\u{00a7}e{}\u{00a7}c' not found",
                    server_name
                ))
                .await;
        }

        match self.proxy.send_player_to_server(target_name, server_name) {
            Ok(()) => {
                self.send_system_chat(&format!(
                    "\u{00a7}aSending \u{00a7}e{}\u{00a7}a to \u{00a7}e{}",
                    target_name, server_name
                ))
                .await
            }
            Err(e) => self.send_system_chat(&format!("\u{00a7}c{}", e)).await,
        }
    }

    async fn handle_send_tab_complete(&self, req: &SCommandSuggestion) -> Result<(), ProxyError> {
        let after_send = &req.command["/send ".len()..];
        let parts: Vec<&str> = after_send.splitn(2, ' ').collect();

        let (start, length, matches) = if parts.len() < 2 {
            let partial = parts.first().copied().unwrap_or("");
            let names: Vec<CommandSuggestion> = self
                .proxy
                .online_player_names()
                .into_iter()
                .filter(|n| n.to_lowercase().starts_with(&partial.to_lowercase()))
                .map(|n| CommandSuggestion::new(n, None))
                .collect();
            ("/send ".len() as i32, partial.len() as i32, names)
        } else {
            let partial = parts[1];
            let offset = "/send ".len() + parts[0].len() + 1;
            (
                offset as i32,
                partial.len() as i32,
                self.server_name_suggestions(partial),
            )
        };

        self.send_suggestions(req.id, start, length, matches).await
    }

    fn server_name_suggestions(&self, partial: &str) -> Vec<CommandSuggestion> {
        let config = self.proxy.config();
        config
            .servers
            .keys()
            .filter(|name| name.starts_with(partial))
            .map(|name| CommandSuggestion::new(name.clone(), None))
            .collect()
    }

    async fn send_suggestions(
        &self,
        id: VarInt,
        start: i32,
        length: i32,
        matches: Vec<CommandSuggestion>,
    ) -> Result<(), ProxyError> {
        let response = CCommandSuggestions::new(
            id,
            VarInt(start),
            VarInt(length),
            matches.into_boxed_slice(),
        );
        self.client
            .send_packet(&response)
            .await
            .map_err(ProxyError::Encode)
    }
}

fn parse_gourd_transfer(payload: &[u8]) -> Option<String> {
    let mut cursor = payload;
    let len = match pumpkin_protocol::codec::var_int::VarInt::decode(&mut cursor) {
        Ok(v) => v.0 as usize,
        Err(e) => {
            log::warn!("gourd:transfer parse: failed to read channel length VarInt: {e:?}");
            return None;
        }
    };
    if cursor.len() < len {
        log::warn!(
            "gourd:transfer parse: channel length {} exceeds remaining payload {}",
            len,
            cursor.len()
        );
        return None;
    }
    let channel = match std::str::from_utf8(&cursor[..len]) {
        Ok(s) => s,
        Err(e) => {
            log::warn!("gourd:transfer parse: channel is not valid UTF-8: {e}");
            return None;
        }
    };
    log::debug!("gourd:transfer parse: channel='{channel}'");
    if channel != "gourd:transfer" {
        return None;
    }
    let data = &cursor[len..];
    let server_name = match std::str::from_utf8(data) {
        Ok(s) => s,
        Err(e) => {
            log::warn!("gourd:transfer parse: server name is not valid UTF-8: {e}");
            return None;
        }
    };
    if server_name.is_empty() {
        log::warn!("gourd:transfer parse: server name is empty");
        return None;
    }
    log::debug!("gourd:transfer parse: server_name='{server_name}'");
    Some(server_name.to_string())
}
