mod firewall;
mod parser;

use anyhow::Result;
use dashmap::DashMap;
use linemux::MuxedLines;
use std::sync::{Arc, RwLock};
use std::time::Instant;

struct IpState {
    count: u32,
    first_seen: Instant,
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();

    // 1. Check Root (Required for IPSet)
    if unsafe { libc::geteuid() } != 0 {
        log::error!("❌ CRITICAL: Run this application with SUDO/ROOT!");
        std::process::exit(1);
    }

    log::info!("🚀 Rust Sentinel started...");

    // 2. Setup Modules
    let fw = firewall::IpSetFirewall::new().expect("Failed to initialize Firewall");
    let parser = parser::Parser::new();
    let detector_state = DashMap::new();

    // Get config access
    let config_lock = parser.get_config();
    let log_path = config_lock.read().unwrap().log_path.clone();

    // 4. Log Watcher (Using Linemux to support log rotation)
    let mut lines = MuxedLines::new()?;

    // Check if log file exists
    if std::path::Path::new(&log_path).exists() {
        lines.add_file(&log_path).await?;
        log::info!("📂 Monitoring Log: {}", log_path);
    } else {
        log::error!("❌ Log file not found: {}", log_path);
        std::process::exit(1);
    }

    // 5. Main Loop
    while let Ok(Some(line)) = lines.next_line().await {
        let log_text = line.line();

        // Parsing
        match parser.parse_line(log_text) {
            parser::LogStatus::InstantBan(ip, reason) => {
                // Check Whitelist
                let is_whitelisted = {
                    let config = config_lock.read().unwrap();
                    config.whitelist.contains(&ip)
                };

                if is_whitelisted {
                    log::debug!("⚪ Whitelist Activity: {}", ip);
                    continue;
                }

                // Instant Ban - No counting required
                let ban_time_seconds = config_lock.read().unwrap().ban_time_seconds;

                log::error!("🚨 [INSTANT BAN TRIGGERED] IP: {} | Reason: {}", ip, reason);

                match fw.ban_ip(&ip, ban_time_seconds) {
                    Ok(_) => log::error!(
                        "⛔ INSTANT BANNED: {} (Duration: {}s)",
                        ip,
                        ban_time_seconds
                    ),
                    Err(e) => log::error!("❌ Failed to Ban IP {}: {}", ip, e),
                }
            }
            parser::LogStatus::Suspicious(ip, reason) => {
                // Check Whitelist
                let is_whitelisted = {
                    let config = config_lock.read().unwrap();
                    config.whitelist.contains(&ip)
                };

                if is_whitelisted {
                    log::debug!("⚪ Whitelist Activity: {}", ip);
                    continue;
                }

                process_attack(&ip, &reason, &detector_state, &fw, &config_lock);
            }
            parser::LogStatus::Clean => {
                // Do nothing for clean requests
            }
        }
    }

    Ok(())
}

fn process_attack(
    ip: &str,
    reason: &str,
    state: &DashMap<String, IpState>,
    fw: &firewall::IpSetFirewall,
    config_lock: &Arc<RwLock<parser::SecurityConfig>>,
) {
    // Read config snapshot for dynamic values
    let (max_retries, window_seconds, ban_time_seconds) = {
        let cfg = config_lock.read().unwrap();
        (cfg.max_retries, cfg.window_seconds, cfg.ban_time_seconds)
    };

    let mut entry = state.entry(ip.to_string()).or_insert(IpState {
        count: 0,
        first_seen: Instant::now(),
    });

    // Reset if time window passed
    if entry.first_seen.elapsed().as_secs() > window_seconds {
        entry.count = 0;
        entry.first_seen = Instant::now();
    }

    entry.count += 1;

    // Log warning
    log::warn!(
        "⚠️  [Audit] IP: {} | Reason: {} | Count: {}/{}",
        ip,
        reason,
        entry.count,
        max_retries
    );

    // Trigger Ban
    if entry.count >= max_retries {
        // Remove from tracking memory
        drop(entry);
        state.remove(ip);

        // Execute Ban
        match fw.ban_ip(ip, ban_time_seconds) {
            Ok(_) => log::error!("⛔ BANNED: {} (Duration: {}s)", ip, ban_time_seconds),
            Err(e) => log::error!("❌ Failed to Ban IP {}: {}", ip, e),
        }
    }
}
