use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use uuid::Uuid;

#[derive(Debug, Deserialize, Serialize)]
pub struct GourdConfig {
    pub bind: String,
    pub online_mode: bool,
    pub motd: String,
    pub max_players: u32,
    pub servers: HashMap<String, ServerEntry>,
    pub default_server: String,
    pub gourd_secret: String,
    pub compression_threshold: i32,
    #[serde(default = "default_login_timeout")]
    pub login_timeout_secs: u64,
    #[serde(default = "default_max_connections_per_ip")]
    pub max_connections_per_ip: u32,
    #[serde(default)]
    pub debug: bool,
    #[serde(default)]
    pub banned_ips: Vec<String>,
    #[serde(default = "default_login_rate_limit")]
    pub login_rate_limit: u32,
    #[serde(default = "default_idle_timeout")]
    pub idle_timeout_secs: u64,
    #[serde(default)]
    pub whitelist_enabled: bool,
    #[serde(default)]
    pub whitelist: Vec<String>,
    #[serde(default)]
    pub blacklist: Vec<String>,
    #[serde(default)]
    pub fallback_server: Option<String>,
}

fn default_login_timeout() -> u64 {
    30
}

fn default_max_connections_per_ip() -> u32 {
    3
}

fn default_login_rate_limit() -> u32 {
    10
}

fn default_idle_timeout() -> u64 {
    120
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ServerEntry {
    pub address: String,
    #[serde(default)]
    pub motd: String,
}

impl Default for GourdConfig {
    fn default() -> Self {
        let mut servers = HashMap::new();
        servers.insert(
            "lobby".to_string(),
            ServerEntry {
                address: "127.0.0.1:25565".to_string(),
                motd: "Lobby".to_string(),
            },
        );
        Self {
            bind: "0.0.0.0:25577".to_string(),
            online_mode: true,
            motd: "A Gourd Proxy".to_string(),
            max_players: 100,
            servers,
            default_server: "lobby".to_string(),
            gourd_secret: Uuid::new_v4().simple().to_string(),
            compression_threshold: 256,
            login_timeout_secs: 30,
            max_connections_per_ip: 3,
            debug: false,
            banned_ips: vec![],
            login_rate_limit: 10,
            idle_timeout_secs: 120,
            whitelist_enabled: false,
            whitelist: vec![],
            blacklist: vec![],
            fallback_server: None,
        }
    }
}

impl GourdConfig {
    pub fn load_or_create(path: &Path) -> Self {
        if path.exists() {
            let content = std::fs::read_to_string(path).expect("Failed to read config file");
            toml::from_str(&content).expect("Failed to parse config file")
        } else {
            let config = Self::default();
            let content = toml::to_string_pretty(&config).expect("Failed to serialize config");
            std::fs::write(path, content).expect("Failed to write default config file");
            log::info!("Generated default config at {}", path.display());
            config
        }
    }

    pub fn try_load(path: &Path) -> Result<Self, String> {
        let content =
            std::fs::read_to_string(path).map_err(|e| format!("Failed to read: {}", e))?;
        toml::from_str(&content).map_err(|e| format!("Failed to parse: {}", e))
    }
}
