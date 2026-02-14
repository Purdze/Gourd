use num_bigint::BigInt;
use pumpkin_protocol::Property;
use serde::Deserialize;
use sha1::{Digest, Sha1};
use thiserror::Error;
use ureq::http::StatusCode;
use uuid::Uuid;

#[derive(Deserialize, Clone, Debug)]
pub struct GameProfile {
    pub id: Uuid,
    pub name: String,
    pub properties: Vec<Property>,
}

#[derive(Error, Debug)]
pub enum AuthError {
    #[error("Authentication servers are down")]
    FailedResponse,
    #[error("Failed to verify username")]
    UnverifiedUsername,
    #[error("Failed to parse JSON into GameProfile")]
    FailedParse,
    #[error("Unknown status code: {0}")]
    UnknownStatusCode(StatusCode),
}

/// Minecraft-style server hash: SHA-1 of (server_id + shared_secret + public_key_der),
/// formatted as a signed hex BigInteger.
pub fn server_hash(server_id: &str, shared_secret: &[u8], public_key_der: &[u8]) -> String {
    let mut hasher = Sha1::new();
    hasher.update(server_id.as_bytes());
    hasher.update(shared_secret);
    hasher.update(public_key_der);
    let hash = hasher.finalize();

    let bigint = BigInt::from_signed_bytes_be(&hash);
    format!("{bigint:x}")
}

pub fn authenticate(username: &str, server_hash: &str) -> Result<GameProfile, AuthError> {
    let mut response = ureq::get("https://sessionserver.mojang.com/session/minecraft/hasJoined")
        .query("username", username)
        .query("serverId", server_hash)
        .call()
        .map_err(|_| AuthError::FailedResponse)?;

    match response.status() {
        StatusCode::OK => {}
        StatusCode::NO_CONTENT => return Err(AuthError::UnverifiedUsername),
        other => return Err(AuthError::UnknownStatusCode(other)),
    }

    let profile: GameProfile = response
        .body_mut()
        .read_json()
        .map_err(|_| AuthError::FailedParse)?;

    Ok(profile)
}
