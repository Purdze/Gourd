use hmac::{Hmac, Mac};
use pumpkin_protocol::codec::var_int::VarInt;
use pumpkin_protocol::ser::NetworkWriteExt;
use sha2::Sha256;
use std::net::SocketAddr;

use crate::auth::GameProfile;

type HmacSha256 = Hmac<Sha256>;

const FORWARDING_VERSION: i32 = 4;

/// Build the Velocity modern forwarding response: HMAC-SHA256 signature + forwarding data.
pub fn build_velocity_response(
    secret: &str,
    client_addr: &SocketAddr,
    profile: &GameProfile,
) -> Vec<u8> {
    let mut data = Vec::new();
    data.write_var_int(&VarInt(FORWARDING_VERSION)).unwrap();
    data.write_string(&client_addr.ip().to_string()).unwrap();
    data.write_uuid(&profile.id).unwrap();
    data.write_string(&profile.name).unwrap();
    data.write_var_int(&VarInt(profile.properties.len() as i32))
        .unwrap();
    for prop in &profile.properties {
        data.write_string(&prop.name).unwrap();
        data.write_string(&prop.value).unwrap();
        data.write_option(&prop.signature, |w, sig| w.write_string(sig))
            .unwrap();
    }

    let mut mac =
        HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC can take key of any size");
    mac.update(&data);
    let signature = mac.finalize().into_bytes();

    let mut result = Vec::with_capacity(32 + data.len());
    result.extend_from_slice(&signature);
    result.extend_from_slice(&data);
    result
}
