# Nginx Sentinel

**Nginx Sentinel** is a lightweight and high-performance Intrusion Detection & Prevention System (IDS/IPS) built using **Rust**. The application is designed to monitor Nginx access logs in real-time, detect attack patterns, and automatically block malicious IP addresses using `ipset` and `iptables`.

## 🚀 Features & Advantages

- **High Performance**: Built with Rust, providing extremely fast execution speed and efficient memory usage.
- **Real-time Monitoring**: Monitors Nginx log files directly (tailing) for instant response to threats.
- **Dynamic Configuration (Hot-Reload)**: Modify security rules, whitelist, or system parameters through YAML file without needing to restart the application.
- **Efficient Blocking**: Uses `ipset` which is much faster than adding thousands of `iptables` rules one by one.
- **Comprehensive Detection**:
  - Sensitive File Scanning (e.g., `.env`, `.git`).
  - CMS & Brute Force Attacks (e.g., WordPress, Laravel).
  - SQL Injection & XSS.
  - Bad User Agents (Bot, Crawler, Scraper).
  - **Instant Ban**: Critical security threats that are banned immediately without scoring.

## 🛠️ How It Works

1.  **Log Tailing**: Sentinel reads new lines from Nginx `access.log` as soon as they are written.
2.  **Parsing & Analysis**: Each line is analyzed using Regex to extract IP, Path, Status Code, and User Agent.
3.  **Pattern Matching**: Extracted data is matched against security rules defined in `sentinel_config.yaml`.
4.  **Scoring System**: If suspicious activity is detected, the IP is given violation points.
5.  **Ban Execution**: If violation points exceed the defined threshold, the IP is immediately blocked at the firewall level (Network Layer).

## ⚖️ Scoring & Banning System

This system uses a **Time Window** mechanism to avoid false positives.

- **Violation Points**: Every time an IP is detected performing suspicious activity (e.g., accessing `.env` and receiving 403), the IP gets **1 point**.
- **Time Window (Window Seconds)**: Points are only valid for a certain duration (default: 60 seconds). If the IP remains quiet after one violation, points will be reset.
- **Threshold (Max Retries)**: If the accumulated points reach the maximum limit (default: 3x) within the time window, the IP is considered an attacker.
- **Action (Banning)**: The offending IP will be added to the `ipset` blacklist and blocked for the specified duration (default: 24 hours).

## 🚨 Instant Ban System

The **Instant Ban** feature provides an additional layer of security for extremely critical threats that should be blocked immediately without going through the scoring system.

### How Instant Ban Differs from Scoring

- **Scoring System**: Tracks violations over time and bans after reaching a threshold (default: 3 attempts in 60 seconds).
- **Instant Ban**: Immediately blocks an IP on the **first detection** of critical attack patterns.

### Instant Ban Triggers

IPs are instantly banned when requesting URLs containing any of these critical patterns:

- **Path Traversal Attacks**: `/etc/passwd`, `/etc/shadow`, `/../..`
- **Remote Code Execution**: `cmd.exe`, `phpshell`, `webshell`, `backdoor`
- **Environment Exposure**: `/proc/self/environ`
- **SQL Injection Keywords**: `union`, `concat`, `updatexml`, `benchmark`, `sleep`, `schema_name`
- **XSS Attack Patterns**: `javascript`, `alert`, `onmouse`, `onload`, `onerror`, `confirm`, `prompt`
- **CMS Exploitation**: `wp-`, `xmlrpc`, `joomla`, `drupal`
- **Sensitive File Access**: `/.env`, `/.git/config`, `backup`, `config`, `shell`

### Configuration Example

```yaml
# Instant Ban Patterns (Banned immediately without counting)
instant_ban:
  - "/etc/passwd"
  - "/etc/shadow"
  - "/../.."
  - "cmd.exe"
  - "/proc/self/environ"
  - "phpshell"
  - "webshell"
  - "union"
  - "alert"
  - "/.env"
```

When an IP makes a request containing any of these patterns, it's immediately added to the firewall blacklist without waiting for multiple violations.

## 📦 Installation & Usage

### Prerequisites

- Linux Server (Ubuntu/Debian/CentOS).
- `ipset` and `iptables` installed (`sudo apt install ipset iptables`).
- Rust Toolchain (for compilation).

### 1. Build Application

```bash
cargo build --release
```

Binary will be available at `target/release/siesta-nginx-sentinel`.

### 2. Configuration

Create or edit the `sentinel_config.yaml` file. Configuration example:

```yaml
# Sensitive file patterns that should not be accessed
sensitive_files:
  - "/.env"
  - "/.git/config"

# CMS attack patterns
cms_attacks:
  - "/wp-admin"
  - "/xmlrpc.php"

# Banned User Agents
bad_user_agents:
  - "curl"
  - "python"
  - "SemrushBot"

# Instant Ban Patterns (immediate ban without scoring)
instant_ban:
  - "/etc/passwd"
  - "/../.."
  - "union"
  - "alert"

# System Configuration
log_path: "/var/log/nginx/access.log"
max_retries: 3 # Ban after 3 attempts
window_seconds: 60 # Reset counter after 60 seconds
ban_time_seconds: 86400 # Ban for 24 hours

# Whitelist (IPs that will never be banned)
whitelist:
  - "127.0.0.1"
  - "::1"
```

### 3. Running Sentinel

The application **must** be run with `root` access or `sudo` because it requires permission to manipulate the firewall.

```bash
sudo SENTINEL_CONFIG=$(pwd)/sentinel_config.yaml ./target/release/siesta-nginx-sentinel
```

### 4. Verify Blocking

To view currently banned IPs:

```bash
sudo ipset list siest_sentinel
```

To manually remove an IP from the ban list:

```bash
sudo ipset del siest_sentinel <IP_ADDRESS>
```
