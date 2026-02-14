use bytes::Bytes;
use pumpkin_protocol::codec::var_int::VarInt;
use pumpkin_protocol::java::packet_decoder::TCPNetworkDecoder;
use pumpkin_protocol::java::packet_encoder::TCPNetworkEncoder;
use pumpkin_protocol::ser::NetworkWriteExt;
use pumpkin_protocol::{
    ClientPacket, CompressionLevel, CompressionThreshold, PacketDecodeError, PacketEncodeError,
    RawPacket,
};
use pumpkin_util::version::MinecraftVersion;
use tokio::io::{BufReader, BufWriter};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::sync::Mutex;

/// Shared packet I/O codec used by both client and backend connections.
pub struct PacketCodec {
    network_reader: Mutex<TCPNetworkDecoder<BufReader<OwnedReadHalf>>>,
    network_writer: Mutex<TCPNetworkEncoder<BufWriter<OwnedWriteHalf>>>,
}

impl PacketCodec {
    pub fn new(reader: OwnedReadHalf, writer: OwnedWriteHalf) -> Self {
        Self {
            network_reader: Mutex::new(TCPNetworkDecoder::new(BufReader::new(reader))),
            network_writer: Mutex::new(TCPNetworkEncoder::new(BufWriter::new(writer))),
        }
    }

    pub fn new_with_compression(
        reader: OwnedReadHalf,
        writer: OwnedWriteHalf,
        threshold: CompressionThreshold,
        level: CompressionLevel,
    ) -> Self {
        let mut decoder = TCPNetworkDecoder::new(BufReader::new(reader));
        let mut encoder = TCPNetworkEncoder::new(BufWriter::new(writer));
        decoder.set_compression(threshold);
        encoder.set_compression((threshold, level));
        Self {
            network_reader: Mutex::new(decoder),
            network_writer: Mutex::new(encoder),
        }
    }

    pub async fn send_packet<P: ClientPacket>(&self, packet: &P) -> Result<(), PacketEncodeError> {
        let mut packet_buf = Vec::new();
        let writer = &mut packet_buf;
        writer
            .write_var_int(&VarInt(P::PACKET_ID.latest_id))
            .unwrap();
        packet
            .write_packet_data(writer, &MinecraftVersion::V_1_21_11)
            .unwrap();
        let mut encoder = self.network_writer.lock().await;
        encoder.write_packet(packet_buf.into()).await?;
        encoder.flush().await
    }

    pub async fn forward_raw_packet(&self, raw: &RawPacket) -> Result<(), PacketEncodeError> {
        let mut buf = Vec::new();
        buf.write_var_int(&VarInt(raw.id)).unwrap();
        buf.extend_from_slice(&raw.payload);
        let mut encoder = self.network_writer.lock().await;
        encoder.write_packet(buf.into()).await?;
        encoder.flush().await
    }

    pub async fn send_raw_bytes(&self, data: Bytes) -> Result<(), PacketEncodeError> {
        let mut encoder = self.network_writer.lock().await;
        encoder.write_packet(data).await?;
        encoder.flush().await
    }

    pub async fn read_raw_packet(&self) -> Result<RawPacket, PacketDecodeError> {
        self.network_reader.lock().await.get_raw_packet().await
    }

    pub async fn set_compression(&self, threshold: CompressionThreshold, level: CompressionLevel) {
        self.network_reader.lock().await.set_compression(threshold);
        self.network_writer
            .lock()
            .await
            .set_compression((threshold, level));
    }

    /// Enable compression only on the reader (decoder) side.
    /// Used when the remote end has compression enabled but didn't
    /// negotiate it (e.g., Pumpkin's Velocity proxy path).
    pub async fn set_read_compression(&self, threshold: CompressionThreshold) {
        self.network_reader.lock().await.set_compression(threshold);
    }

    pub async fn set_encryption(&self, key: &[u8; 16]) {
        self.network_reader.lock().await.set_encryption(key);
        self.network_writer.lock().await.set_encryption(key);
    }
}
