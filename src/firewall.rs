use anyhow::{Result, anyhow};
use log::info;
use std::process::Command;

pub struct IpSetFirewall {
    set_name: String,
}

impl IpSetFirewall {
    pub fn new() -> Result<Self> {
        let set_name = "siest_sentinel".to_string();

        // 1. Create IPSet (hash:ip type with timeout support)
        // -exist ensures no error if set already exists
        let output = Command::new("ipset")
            .args(&["create", &set_name, "hash:ip", "timeout", "0", "-exist"])
            .output()
            .map_err(|e| anyhow!("Failed to execute ipset: {}", e))?;

        if !output.status.success() {
            return Err(anyhow!(
                "Error creating ipset: {}",
                String::from_utf8_lossy(&output.stderr)
            ));
        }

        // 2. Link IPSet to IPTables (INPUT Chain)
        // Check first if rule already exists
        let check = Command::new("iptables")
            .args(&[
                "-C",
                "INPUT",
                "-m",
                "set",
                "--match-set",
                &set_name,
                "src",
                "-j",
                "DROP",
            ])
            .output();

        // If rule doesn't exist, add it at the first position (-I INPUT 1)
        if check.is_err() || !check.unwrap().status.success() {
            Command::new("iptables")
                .args(&[
                    "-I",
                    "INPUT",
                    "1",
                    "-m",
                    "set",
                    "--match-set",
                    &set_name,
                    "src",
                    "-j",
                    "DROP",
                ])
                .output()
                .map_err(|e| anyhow!("Failed to update iptables: {}", e))?;
            info!("✅ Firewall: IPTables rule installed successfully.");
        } else {
            info!("✅ Firewall: IPTables rule already active.");
        }

        Ok(Self { set_name })
    }

    pub fn ban_ip(&self, ip: &str, duration: usize) -> Result<()> {
        // Command: ipset add siest_sentinel 1.2.3.4 timeout 3600 -exist
        let output = Command::new("ipset")
            .args(&[
                "add",
                &self.set_name,
                ip,
                "timeout",
                &duration.to_string(),
                "-exist",
            ])
            .output()?;

        if output.status.success() {
            Ok(())
        } else {
            Err(anyhow!(
                "Failed to ban IP: {}",
                String::from_utf8_lossy(&output.stderr)
            ))
        }
    }
}
