use log::{error, info};
use notify::{Event, RecommendedWatcher, RecursiveMode, Watcher};
use regex::Regex;
use serde::Deserialize;
use std::env;
use std::fs;
use std::path::Path;
use std::sync::{Arc, RwLock};

#[derive(Debug, Deserialize, Clone)]
pub struct SecurityConfig {
    #[serde(default)]
    pub sensitive_files: Vec<String>,
    #[serde(default)]
    pub cms_attacks: Vec<String>,
    #[serde(default = "default_log_path")]
    pub log_path: String,
    #[serde(default = "default_max_retries")]
    pub max_retries: u32,
    #[serde(default = "default_window_seconds")]
    pub window_seconds: u64,
    #[serde(default = "default_ban_time_seconds")]
    pub ban_time_seconds: usize,
    #[serde(default)]
    pub whitelist: Vec<String>,
    #[serde(default)]
    pub bad_user_agents: Vec<String>,
    #[serde(default)]
    pub instant_ban: Vec<String>,
}

fn default_log_path() -> String {
    "/var/log/nginx/access.log".to_string()
}
fn default_max_retries() -> u32 {
    3
}
fn default_window_seconds() -> u64 {
    60
}
fn default_ban_time_seconds() -> usize {
    86400
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            sensitive_files: vec![],
            cms_attacks: vec![],
            log_path: default_log_path(),
            max_retries: default_max_retries(),
            window_seconds: default_window_seconds(),
            ban_time_seconds: default_ban_time_seconds(),
            whitelist: vec![],
            bad_user_agents: vec![],
            instant_ban: vec![],
        }
    }
}

pub enum LogStatus {
    Clean,
    Suspicious(String, String), // (IP, Reason)
    InstantBan(String, String), // (IP, Reason) - for immediate ban without counting
}

pub struct Parser {
    log_regex: Regex,
    config: Arc<RwLock<SecurityConfig>>,
    // Keep watcher alive
    _watcher: Option<Arc<std::sync::Mutex<RecommendedWatcher>>>,
}

impl Parser {
    pub fn new() -> Self {
        // Regex Nginx Combined Log Format
        // Group 1: IP, Group 3: Path, Group 4: Status Code, Group 5: User Agent
        let log_regex = Regex::new(
            r#"^(\S+) .*? "(GET|POST|HEAD|PUT|DELETE|PATCH) (.*?) .*?" (\d+) .*? ".*?" "(.*?)""#,
        )
        .expect("Fatal: Regex invalid");

        let config = Arc::new(RwLock::new(SecurityConfig::default()));
        let mut watcher_guard = None;

        let config_path =
            env::var("SENTINEL_CONFIG").unwrap_or_else(|_| "sentinel_config.yaml".to_string());

        if Path::new(&config_path).exists() {
            info!("Loading config from: {}", config_path);
            // Load initial config
            Self::load_config(&config_path, &config);

            // Setup watcher
            let config_clone = config.clone();
            let path_str = config_path.clone();

            let update_fn = move |res: notify::Result<Event>| {
                match res {
                    Ok(event) => {
                        // Reload on Modify or Create (in case of atomic replace)
                        if event.kind.is_modify() || event.kind.is_create() {
                            info!("Config file changed, reloading...");
                            Self::load_config(&path_str, &config_clone);
                        }
                    }
                    Err(e) => error!("Watch error: {:?}", e),
                }
            };

            match notify::recommended_watcher(update_fn) {
                Ok(mut watcher) => {
                    if let Err(e) =
                        watcher.watch(Path::new(&config_path), RecursiveMode::NonRecursive)
                    {
                        error!("Failed to watch config file: {}", e);
                    } else {
                        info!("Watching config file: {}", config_path);
                        watcher_guard = Some(Arc::new(std::sync::Mutex::new(watcher)));
                    }
                }
                Err(e) => error!("Failed to create watcher: {}", e),
            }
        } else {
            info!(
                "Config file '{}' not found. Security patterns are EMPTY.",
                config_path
            );
        }

        Self {
            log_regex,
            config,
            _watcher: watcher_guard,
        }
    }

    fn load_config(path: &str, config: &Arc<RwLock<SecurityConfig>>) {
        match fs::read_to_string(path) {
            Ok(contents) => match serde_yaml::from_str::<SecurityConfig>(&contents) {
                Ok(new_config) => {
                    let mut w = config.write().unwrap();
                    *w = new_config;
                    info!("Config loaded successfully from {}", path);
                }
                Err(e) => error!("Failed to parse YAML config: {}", e),
            },
            Err(e) => error!("Failed to read config file {}: {}", path, e),
        }
    }

    pub fn parse_line(&self, line: &str) -> LogStatus {
        if let Some(caps) = self.log_regex.captures(line) {
            let ip = caps.get(1).map(|m| m.as_str()).unwrap_or("");
            let path = caps.get(3).map(|m| m.as_str()).unwrap_or("").to_lowercase();
            let status_str = caps.get(4).map(|m| m.as_str()).unwrap_or("200");
            let status: u16 = status_str.parse().unwrap_or(200);

            // Acquire read lock
            let config = self.config.read().unwrap();

            // --- DETECTION LOGIC ---

            // 0. Instant Ban Check (HIGHEST PRIORITY - Check first!)
            for pattern in &config.instant_ban {
                if path.contains(pattern) {
                    return LogStatus::InstantBan(
                        ip.to_string(),
                        format!("Instant Ban: {}", pattern),
                    );
                }
            }

            // 1. Sensitive File Scanning (Must be 403 Forbidden or 404 Not Found)
            if status == 404 || status == 403 {
                for file in &config.sensitive_files {
                    if path.contains(file) {
                        return LogStatus::Suspicious(ip.to_string(), format!("Probe: {}", file));
                    }
                }
            }

            // 2. Brute Force Login / CMS Attacks (Status 400/401/404)
            if status == 401 || status == 400 || status == 404 {
                for attack in &config.cms_attacks {
                    if path.contains(attack) {
                        return LogStatus::Suspicious(
                            ip.to_string(),
                            format!("CMS/Auth Attack: {}", attack),
                        );
                    }
                }
            }

            // 4. SQL Injection / XSS
            if path.contains("union+select") || path.contains("eval(") || path.contains("<script>")
            {
                return LogStatus::Suspicious(ip.to_string(), "Injection Attempt".to_string());
            }

            // 5. Bad User Agent
            let user_agent = caps.get(5).map(|m| m.as_str()).unwrap_or("");
            for bad_ua in &config.bad_user_agents {
                if user_agent.contains(bad_ua) {
                    return LogStatus::Suspicious(
                        ip.to_string(),
                        format!("Bad User Agent: {}", user_agent),
                    );
                }
            }
        }

        LogStatus::Clean
    }

    pub fn get_config(&self) -> Arc<RwLock<SecurityConfig>> {
        self.config.clone()
    }
}
