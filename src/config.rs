use crate::utils;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct Config {
    pub username: Option<String>,
    pub password: Option<String>,
    pub ip: Option<String>,
    pub ssh_key_path: Option<String>,
    pub sudo_username: Option<String>,
    pub sudo_password: Option<String>,
    pub info_file_path: Option<String>,
    #[serde(default = "default_keep_root_password")]
    pub keep_root_password: bool,
    #[serde(default = "default_use_root_ssh_key")]
    pub use_root_ssh_key: bool,
    pub new_user_ssh_key_path: Option<String>,
}

fn default_keep_root_password() -> bool {
    true // Default to keeping root password authentication
}

fn default_use_root_ssh_key() -> bool {
    true // Default to trying SSH key for root connection
}

impl Config {
    pub fn load() -> Result<Self> {
        let config_path = Self::config_file_path()?;
        
        if !config_path.exists() {
            return Ok(Config::default());
        }
        
        let content = fs::read_to_string(&config_path)
            .context("Failed to read config file")?;
        
        let config: Config = serde_json::from_str(&content)
            .context("Failed to parse config file")?;
        
        Ok(config)
    }
    
    pub fn save(&self) -> Result<()> {
        let config_path = Self::config_file_path()?;
        
        if let Some(parent) = config_path.parent() {
            fs::create_dir_all(parent)
                .context("Failed to create config directory")?;
        }
        
        let content = serde_json::to_string_pretty(self)
            .context("Failed to serialize config")?;
        
        fs::write(&config_path, content)
            .context("Failed to write config file")?;
        
        Ok(())
    }
    
    pub fn set_username(&mut self, username: String) {
        self.username = Some(username);
    }
    
    pub fn set_password(&mut self, password: String) {
        self.password = Some(password);
    }
    
    pub fn set_ip(&mut self, ip: String) {
        self.ip = Some(ip);
    }
    
    pub fn set_ssh_key_path(&mut self, path: String) -> Result<()> {
        let expanded_path = utils::validate_file_path(&path)?;
        self.ssh_key_path = Some(expanded_path.to_string_lossy().to_string());
        Ok(())
    }
    
    pub fn set_sudo_username(&mut self, username: String) {
        self.sudo_username = Some(username);
    }
    
    pub fn set_sudo_password(&mut self, password: String) {
        self.sudo_password = Some(password);
    }
    
    pub fn set_info_file_path(&mut self, path: String) -> Result<()> {
        let expanded_path = utils::validate_dir_path(&path)?;
        self.info_file_path = Some(expanded_path.to_string_lossy().to_string());
        Ok(())
    }
    
    pub fn set_keep_root_password(&mut self, keep: bool) {
        self.keep_root_password = keep;
    }
    
    pub fn set_use_root_ssh_key(&mut self, use_key: bool) {
        self.use_root_ssh_key = use_key;
    }
    
    pub fn set_new_user_ssh_key_path(&mut self, path: String) -> Result<()> {
        let expanded_path = utils::validate_file_path(&path)?;
        self.new_user_ssh_key_path = Some(expanded_path.to_string_lossy().to_string());
        Ok(())
    }
    
    pub fn display(&self) {
        println!("VPS Setup Configuration:");
        println!();
        println!("🔐 INITIAL CONNECTION:");
        println!("  Root Username: {}", self.username.as_deref().unwrap_or("Not set"));
        println!("  Root Password: {}", if self.password.is_some() { "***SET***" } else { "Not set" });
        println!("  Server IP: {}", self.ip.as_deref().unwrap_or("Not set"));
        println!("  Root SSH Key: {}", if self.ssh_key_path.is_some() { 
            format!("{} ({})", 
                self.ssh_key_path.as_deref().unwrap(),
                if self.use_root_ssh_key { "enabled" } else { "disabled" }
            )
        } else { 
            "Not set".to_string() 
        });
        println!();
        println!("👤 NEW USER TO CREATE:");
        println!("  Username: {}", self.sudo_username.as_deref().unwrap_or("Not set"));
        println!("  Password: {}", if self.sudo_password.is_some() { "***SET***" } else { "Not set" });
        println!("  SSH Key: {}", self.new_user_ssh_key_path.as_deref().unwrap_or("Not set (will copy root SSH key)"));
        println!("  (Will have sudo privileges without password prompts)");
        println!();
        println!("🔧 SECURITY SETTINGS:");
        println!("  Use Root SSH Key: {} (try SSH key first for root connection)", 
            if self.use_root_ssh_key { "YES" } else { "NO" });
        println!("  Keep Root Password: {} (root can connect via {})", 
            if self.keep_root_password { "YES" } else { "NO" },
            if self.keep_root_password { "SSH key + password" } else { "SSH key only" });
        println!();
        println!("📄 OUTPUT:");
        println!("  Info File: {}", self.info_file_path.as_deref().unwrap_or("./vps_setup_info.txt (default)"));
        println!();
        
        // Show setup readiness status
        println!("🚦 SETUP READINESS:");
        let missing_fields = self.get_missing_required_fields();
        if missing_fields.is_empty() {
            println!("  ✅ Ready for setup! All required fields are configured.");
        } else {
            println!("  ❌ Missing required fields: {}", missing_fields.join(", "));
            println!("     Use 'set <field>' commands to configure missing fields.");
        }
        println!();
        
        println!("After setup completes:");
        if self.keep_root_password {
            println!("  • Root can connect via SSH key OR password");
        } else {
            println!("  • Root can only connect via SSH key (password disabled)");
        }
        println!("  • New user can connect via SSH key OR password");
        println!("  • New user has full sudo access without password prompts");
    }
    
    fn get_missing_required_fields(&self) -> Vec<String> {
        let mut missing = Vec::new();
        
        if self.username.is_none() {
            missing.push("username".to_string());
        }
        if self.ip.is_none() {
            missing.push("ip".to_string());
        }
        if self.ssh_key_path.is_none() {
            missing.push("ssh_key".to_string());
        }
        if self.sudo_username.is_none() {
            missing.push("sudo_username".to_string());
        }
        if self.sudo_password.is_none() {
            missing.push("sudo_password".to_string());
        }
        
        // If root SSH key is disabled, we need a password
        if !self.use_root_ssh_key && self.password.is_none() {
            missing.push("password (required when root SSH key is disabled)".to_string());
        }
        
        missing
    }
    
    pub fn is_valid_for_connection(&self) -> bool {
        self.username.is_some() && self.ip.is_some()
    }
    
    pub fn is_valid_for_key_copy(&self) -> bool {
        self.username.is_some() && self.password.is_some() && self.ip.is_some() && self.ssh_key_path.is_some()
    }
        
    fn config_file_path() -> Result<PathBuf> {
        let home_dir = dirs::home_dir()
            .context("Failed to get home directory")?;
        
        Ok(home_dir.join(".config").join("autovps").join("config.json"))
    }
}