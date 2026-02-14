use crossbeam::atomic::AtomicCell;
use pumpkin_protocol::{CompressionLevel, CompressionThreshold, ConnectionState};
use std::net::SocketAddr;
use std::ops::Deref;
use tokio::net::TcpStream;

use crate::codec::PacketCodec;

/// Client-facing connection (MC client <-> proxy).
/// Packet I/O methods are provided by `PacketCodec` via `Deref`.
pub struct ClientConnection {
    codec: PacketCodec,
    pub connection_state: AtomicCell<ConnectionState>,
    pub address: SocketAddr,
}

impl Deref for ClientConnection {
    type Target = PacketCodec;
    fn deref(&self) -> &PacketCodec {
        &self.codec
    }
}

impl ClientConnection {
    pub fn new(stream: TcpStream, address: SocketAddr) -> Self {
        stream.set_nodelay(true).ok();
        let (reader, writer) = stream.into_split();
        Self {
            codec: PacketCodec::new(reader, writer),
            connection_state: AtomicCell::new(ConnectionState::HandShake),
            address,
        }
    }

    /// Create a ClientConnection after login was completed via raw TCP I/O,
    /// with compression already negotiated.
    pub fn new_post_login(
        stream: TcpStream,
        address: SocketAddr,
        compression: Option<(CompressionThreshold, CompressionLevel)>,
    ) -> Self {
        stream.set_nodelay(true).ok();
        let (reader, writer) = stream.into_split();
        let codec = if let Some((threshold, level)) = compression {
            PacketCodec::new_with_compression(reader, writer, threshold, level)
        } else {
            PacketCodec::new(reader, writer)
        };
        Self {
            codec,
            connection_state: AtomicCell::new(ConnectionState::Config),
            address,
        }
    }
}
