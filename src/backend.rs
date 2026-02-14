use bytes::Bytes;
use crossbeam::atomic::AtomicCell;
use pumpkin_data::packet::CURRENT_MC_PROTOCOL;
use pumpkin_protocol::codec::var_int::VarInt;
use pumpkin_protocol::java::client::login::{
    CLoginDisconnect, CLoginPluginRequest, CLoginSuccess, CSetCompression,
};
use pumpkin_protocol::java::server::handshake::SHandShake;
use pumpkin_protocol::java::server::login::{
    SLoginAcknowledged, SLoginPluginResponse, SLoginStart,
};
use pumpkin_protocol::packet::MultiVersionJavaPacket;
use pumpkin_protocol::ser::{NetworkReadExt, NetworkWriteExt};
use pumpkin_protocol::{
    ConnectionState, PacketDecodeError, PacketEncodeError, RawPacket, ServerPacket,
};
use std::collections::VecDeque;
use std::net::SocketAddr;
use std::time::Duration;
use thiserror::Error;
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use uuid::Uuid;

use crate::auth::GameProfile;
use crate::codec::PacketCodec;
use crate::forwarding;

const VELOCITY_CHANNEL: &str = "velocity:player_info";
const BACKEND_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const BACKEND_LOGIN_TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Error, Debug)]
pub enum BackendError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Packet encode error: {0}")]
    Encode(#[from] PacketEncodeError),
    #[error("Packet decode error: {0}")]
    Decode(#[from] PacketDecodeError),
    #[error("Reading error: {0}")]
    Reading(#[from] pumpkin_protocol::ser::ReadingError),
    #[error("Backend rejected login: {0}")]
    Rejected(String),
    #[error("Connection timed out")]
    Timeout,
}

/// Backend connection (proxy <-> PumpkinMC server).
/// Wraps a `PacketCodec` and adds a buffer for pre-read packets
/// (used during compression auto-detection after login).
pub struct BackendConnection {
    codec: PacketCodec,
    pub connection_state: AtomicCell<ConnectionState>,
    buffered: Mutex<VecDeque<RawPacket>>,
}

impl BackendConnection {
    /// Read the next packet, returning any buffered packet first.
    pub async fn read_raw_packet(&self) -> Result<RawPacket, PacketDecodeError> {
        {
            let mut buf = self.buffered.lock().await;
            if let Some(pkt) = buf.pop_front() {
                return Ok(pkt);
            }
        }
        self.codec.read_raw_packet().await
    }

    pub async fn forward_raw_packet(&self, raw: &RawPacket) -> Result<(), PacketEncodeError> {
        self.codec.forward_raw_packet(raw).await
    }

    pub async fn send_raw_bytes(&self, data: Bytes) -> Result<(), PacketEncodeError> {
        self.codec.send_raw_bytes(data).await
    }

    pub async fn send_packet<P: pumpkin_protocol::ClientPacket>(
        &self,
        packet: &P,
    ) -> Result<(), PacketEncodeError> {
        self.codec.send_packet(packet).await
    }

    pub async fn set_compression(&self, threshold: usize, level: u32) {
        self.codec.set_compression(threshold, level).await;
    }
}

impl BackendConnection {
    /// Connect to a backend and perform the login handshake with Velocity forwarding.
    pub async fn connect(
        addr: SocketAddr,
        player_name: &str,
        player_uuid: Uuid,
        profile: &GameProfile,
        gourd_secret: &str,
        client_addr: &SocketAddr,
    ) -> Result<Self, BackendError> {
        let stream = tokio::time::timeout(BACKEND_CONNECT_TIMEOUT, TcpStream::connect(addr))
            .await
            .map_err(|_| BackendError::Timeout)??;
        let (reader, writer) = stream.into_split();

        let conn = Self {
            codec: PacketCodec::new(reader, writer),
            connection_state: AtomicCell::new(ConnectionState::HandShake),
            buffered: Mutex::new(VecDeque::new()),
        };

        conn.send_packet(&SHandShake {
            protocol_version: VarInt(CURRENT_MC_PROTOCOL as i32),
            server_address: addr.ip().to_string(),
            server_port: addr.port(),
            next_state: ConnectionState::Login,
        })
        .await?;
        conn.connection_state.store(ConnectionState::Login);

        conn.send_packet(&SLoginStart {
            name: player_name.to_string(),
            uuid: player_uuid,
        })
        .await?;

        let mut compression_negotiated = false;

        tokio::time::timeout(BACKEND_LOGIN_TIMEOUT, async {
            loop {
                let raw = conn.read_raw_packet().await?;
                let mut payload = &raw.payload[..];

                if raw.id == CSetCompression::PACKET_ID {
                    let packet = CSetCompression::read(&raw.payload[..])?;
                    let threshold_raw = packet.threshold.0;
                    if threshold_raw < 0 {
                        log::warn!(
                            "Backend sent negative compression threshold: {}",
                            threshold_raw
                        );
                        continue;
                    }
                    let threshold = threshold_raw as usize;
                    log::debug!("Backend set compression threshold: {}", threshold);
                    conn.set_compression(threshold, 6).await;
                    compression_negotiated = true;
                } else if raw.id == CLoginPluginRequest::PACKET_ID {
                    let message_id = payload.get_var_int()?;
                    let channel = payload.get_string()?;

                    let mut response_buf = Vec::new();
                    response_buf
                        .write_var_int(&VarInt(SLoginPluginResponse::PACKET_ID.latest_id))
                        .unwrap();
                    response_buf.write_var_int(&message_id).unwrap();

                    if channel == VELOCITY_CHANNEL {
                        log::debug!(
                            "Received velocity:player_info request, sending forwarding response"
                        );
                        response_buf.write_bool(true).unwrap();
                        response_buf.extend_from_slice(
                            &forwarding::build_velocity_response(
                                gourd_secret,
                                client_addr,
                                profile,
                            ),
                        );
                    } else {
                        log::debug!(
                            "Unknown plugin channel: {}, responding unsuccessful",
                            channel
                        );
                        response_buf.write_bool(false).unwrap();
                    }

                    conn.send_raw_bytes(response_buf.into()).await?;
                } else if raw.id == CLoginSuccess::PACKET_ID {
                    log::debug!("Backend login success, sending LoginAcknowledged");
                    conn.send_packet(&SLoginAcknowledged).await?;
                    conn.connection_state.store(ConnectionState::Config);
                    break;
                } else if raw.id == CLoginDisconnect::PACKET_ID {
                    let reason = payload
                        .get_string()
                        .unwrap_or_else(|_| "Unknown reason".to_string());
                    return Err(BackendError::Rejected(reason));
                } else {
                    log::warn!(
                        "Unexpected packet during backend login: id=0x{:02X}",
                        raw.id
                    );
                }
            }
            Ok::<(), BackendError>(())
        })
        .await
        .map_err(|_| BackendError::Timeout)??;

        // Read the first Config packet and detect compression mismatch
        // (some backends use compression framing without sending CSetCompression).
        let first = conn.codec.read_raw_packet().await?;

        if compression_negotiated {
            log::debug!(
                "First config packet: id={} (0x{:02X}), payload={}B (compression negotiated)",
                first.id,
                first.id,
                first.payload.len()
            );
            conn.buffered.lock().await.push_back(first);
        } else {
            // No CSetCompression received — check if compression framing is
            // present anyway (data_length misread as packet_id).
            let compression_detected = if first.id == 0 && !first.payload.is_empty() {
                // data_length=0: payload contains [actual_id | actual_data]
                let mut probe = &first.payload[..];
                probe
                    .get_var_int()
                    .ok()
                    .is_some_and(|vi| vi.0 >= 0 && vi.0 <= 127)
            } else if first.id > 0 && !first.payload.is_empty() && first.payload[0] == 0x78 {
                // data_length>0: payload is zlib-compressed (0x78 = deflate header)
                true
            } else {
                false
            };

            if compression_detected {
                log::warn!(
                    "Backend compression detected without CSetCompression \
                     (first config packet: id={}, payload={}B). \
                     Enabling read-side compression on backend codec.",
                    first.id,
                    first.payload.len()
                );

                // Read-side only: the backend didn't negotiate compression,
                // so it doesn't expect compressed frames from us.
                conn.codec.set_read_compression(2_097_152).await;

                if first.id == 0 {
                    // Re-interpret the misread uncompressed packet
                    let mut cursor = &first.payload[..];
                    let actual_id = cursor
                        .get_var_int()
                        .map_err(BackendError::Reading)?
                        .0;
                    let actual_payload = Bytes::copy_from_slice(cursor);
                    let corrected = RawPacket {
                        id: actual_id,
                        payload: actual_payload,
                    };
                    log::debug!(
                        "Corrected first config packet: id={} (0x{:02X}), payload={}B",
                        corrected.id,
                        corrected.id,
                        corrected.payload.len()
                    );
                    conn.buffered.lock().await.push_back(corrected);
                } else {
                    // Can't recover the compressed packet — let the next read
                    // proceed with compression enabled.
                    log::warn!(
                        "First config packet was compressed (data_length={}). \
                         It could not be recovered — the backend may need to \
                         retransmit during config phase.",
                        first.id
                    );
                }
            } else {
                log::debug!(
                    "First config packet: id={} (0x{:02X}), payload={}B (no compression mismatch)",
                    first.id,
                    first.id,
                    first.payload.len()
                );
                conn.buffered.lock().await.push_back(first);
            }
        }

        Ok(conn)
    }
}
