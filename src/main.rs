mod auth;
mod backend;
mod client;
mod codec;
mod config;
mod forwarding;
mod proxy;
mod session;

use config::GourdConfig;
use proxy::ProxyServer;
use rsa::RsaPrivateKey;
use rsa::pkcs8::EncodePublicKey;
use rsa::rand_core::OsRng;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;

/// Tracks active connections per IP to prevent connection flooding.
struct ConnectionLimiter {
    active: StdMutex<HashMap<IpAddr, u32>>,
}

impl ConnectionLimiter {
    fn new() -> Self {
        Self {
            active: StdMutex::new(HashMap::new()),
        }
    }

    fn try_acquire(&self, ip: IpAddr, max_per_ip: u32) -> bool {
        let mut map = self.active.lock().unwrap();
        let count = map.entry(ip).or_insert(0);
        if *count >= max_per_ip {
            false
        } else {
            *count += 1;
            true
        }
    }

    fn release(&self, ip: IpAddr) {
        let mut map = self.active.lock().unwrap();
        if let Some(count) = map.get_mut(&ip) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                map.remove(&ip);
            }
        }
    }
}

#[tokio::main]
async fn main() {
    let config_path = PathBuf::from("config.toml");
    let config = GourdConfig::load_or_create(&config_path);

    let log_level = if config.debug {
        log::Level::Debug
    } else {
        log::Level::Info
    };
    simple_logger::init_with_level(log_level).unwrap();
    let secret_preview = if config.gourd_secret.len() > 8 {
        &config.gourd_secret[..8]
    } else {
        &config.gourd_secret
    };
    log::info!(
        "Loaded config: bind={}, secret={}...",
        config.bind,
        secret_preview
    );

    let bind_addr = config.bind.clone();

    let rsa_key = RsaPrivateKey::new(&mut OsRng, 2048).expect("Failed to generate RSA keypair");
    let public_key = rsa_key.to_public_key();
    let der_public_key = public_key
        .to_public_key_der()
        .expect("Failed to DER-encode public key")
        .to_vec();

    log::info!(
        "RSA keypair generated ({} byte public key)",
        der_public_key.len()
    );

    let (shutdown_tx, _shutdown_rx) = watch::channel(false);
    let limiter = Arc::new(ConnectionLimiter::new());

    let proxy = Arc::new(ProxyServer::new(
        config,
        Arc::new(rsa_key),
        Arc::new(der_public_key),
        shutdown_tx.clone(),
    ));

    spawn_config_watcher(config_path, proxy.clone());
    spawn_health_checker(proxy.clone());

    let listener = TcpListener::bind(&bind_addr)
        .await
        .expect("Failed to bind TCP listener");
    log::info!("Gourd proxy listening on {}", bind_addr);

    let mut tasks = tokio::task::JoinSet::new();

    loop {
        tokio::select! {
            result = listener.accept() => {
                match result {
                    Ok((stream, addr)) => {
                        let ip = addr.ip();
                        let config = proxy.config();
                        let ip_str = ip.to_string();
                        if config.banned_ips.contains(&ip_str) {
                            log::warn!("Banned IP {} rejected", ip);
                            drop(stream);
                            continue;
                        }
                        if !limiter.try_acquire(ip, config.max_connections_per_ip) {
                            log::warn!("Connection limit exceeded for {}, rejecting", ip);
                            drop(stream);
                            continue;
                        }
                        let proxy = proxy.clone();
                        let limiter = limiter.clone();
                        tasks.spawn(async move {
                            if let Err(e) = proxy.handle_connection(stream, addr).await {
                                log::error!("Connection from {} failed: {}", addr, e);
                            }
                            limiter.release(ip);
                        });
                    }
                    Err(e) => {
                        log::error!("Failed to accept connection: {}", e);
                    }
                }
            }
            _ = tokio::signal::ctrl_c() => {
                log::info!("Shutdown signal received, draining connections...");
                break;
            }
        }
    }

    let _ = shutdown_tx.send(true);

    let active = tasks.len();
    if active > 0 {
        log::info!("Waiting for {} active connection(s) to close...", active);
        let drain = async { while tasks.join_next().await.is_some() {} };
        match tokio::time::timeout(Duration::from_secs(10), drain).await {
            Ok(()) => log::info!("All connections drained"),
            Err(_) => log::warn!(
                "Drain timeout, {} connection(s) forcefully closed",
                tasks.len()
            ),
        }
    }

    log::info!("Gourd proxy shut down");
}

fn spawn_config_watcher(path: PathBuf, proxy: Arc<ProxyServer>) {
    tokio::spawn(async move {
        let mut last_mtime = std::fs::metadata(&path).and_then(|m| m.modified()).ok();
        loop {
            tokio::time::sleep(Duration::from_secs(30)).await;
            let current_mtime = std::fs::metadata(&path).and_then(|m| m.modified()).ok();
            if current_mtime != last_mtime {
                last_mtime = current_mtime;
                match GourdConfig::try_load(&path) {
                    Ok(new_config) => {
                        log::info!("Config reloaded from {}", path.display());
                        proxy.reload_config(new_config);
                    }
                    Err(e) => log::warn!("Failed to reload config: {}", e),
                }
            }
        }
    });
}

fn spawn_health_checker(proxy: Arc<ProxyServer>) {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(15)).await;
            let config = proxy.config();
            let mut health = HashMap::new();
            for (name, server) in &config.servers {
                let addr: Result<SocketAddr, _> = server.address.parse();
                let is_healthy = match addr {
                    Ok(addr) => {
                        tokio::time::timeout(Duration::from_secs(3), TcpStream::connect(addr))
                            .await
                            .map(|r| r.is_ok())
                            .unwrap_or(false)
                    }
                    Err(_) => false,
                };
                health.insert(name.clone(), is_healthy);
            }
            proxy.update_server_health(health);
        }
    });
}
