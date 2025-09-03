use crate::utils;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum SetupMode {
    RootOnly,    // Configure root user only, disable password auth
    NewUser,     // Create new user with sudo privileges 
    Script,      // Deploy and run scripts
}

impl Default for SetupMode {
    fn default() -> Self {
        SetupMode::NewUser
    }
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct Config {
    #[serde(default)]
    pub mode: SetupMode,
    pub username: Option<String>,
    pub password: Option<String>,
    pub ip: Option<String>,
    pub root_ssh_key: Option<String>,
    pub sudo_username: Option<String>,
    pub sudo_password: Option<String>,
    pub user_ssh_key: Option<String>,
    pub script_path: Option<String>,
    pub script_args: Option<String>,
    pub info_file_path: Option<String>,
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
    
    pub fn set_mode(&mut self, mode_str: &str) -> Result<()> {
        self.mode = match mode_str.to_lowercase().as_str() {
            "root" | "rootonly" | "root-only" => SetupMode::RootOnly,
            "user" | "newuser" | "new-user" => SetupMode::NewUser,
            "script" | "deploy" => SetupMode::Script,
            _ => return Err(anyhow::anyhow!("Invalid mode. Available: root, user, script")),
        };
        Ok(())
    }
    
    pub fn set_root_ssh_key(&mut self, path: String) -> Result<()> {
        let expanded_path = utils::validate_file_path(&path)?;
        self.root_ssh_key = Some(expanded_path.to_string_lossy().to_string());
        Ok(())
    }
    
    pub fn set_user_ssh_key(&mut self, path: String) -> Result<()> {
        let expanded_path = utils::validate_file_path(&path)?;
        self.user_ssh_key = Some(expanded_path.to_string_lossy().to_string());
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
    
    
    pub fn set_script_path(&mut self, path: String) -> Result<()> {
        let expanded_path = utils::validate_file_path(&path)?;
        self.script_path = Some(expanded_path.to_string_lossy().to_string());
        Ok(())
    }
    
    pub fn set_script_args(&mut self, args: String) {
        self.script_args = Some(args);
    }
    
    pub fn get_mode(&self) -> String {
        match self.mode {
            SetupMode::RootOnly => "ROOT-ONLY",
            SetupMode::NewUser => "NEW-USER",
            SetupMode::Script => "SCRIPT",
        }.to_string()
    }
    
    pub fn display(&self) {
        println!("VPS Setup Configuration - Mode: {}", self.get_mode());
        println!();
        
        println!("🔐 CONNECTION:");
        println!("  Username: {}", self.username.as_deref().unwrap_or("Not set"));
        println!("  Password: {}", if self.password.is_some() { "***SET***" } else { "Not set" });
        println!("  Server IP: {}", self.ip.as_deref().unwrap_or("Not set"));
        println!();
        
        match self.mode {
            SetupMode::RootOnly => {
                println!("🔧 ROOT-ONLY MODE:");
                println!("  Root SSH Key: {}", self.root_ssh_key.as_deref().unwrap_or("Not set"));
                println!("  • Will disable root password authentication");
                println!("  • Only SSH key access for root user");
            }
            SetupMode::NewUser => {
                println!("👤 NEW USER MODE:");
                println!("  Root SSH Key: {}", self.root_ssh_key.as_deref().unwrap_or("Not set"));
                println!("  New Username: {}", self.sudo_username.as_deref().unwrap_or("Not set"));
                println!("  New Password: {}", if self.sudo_password.is_some() { "***SET***" } else { "Not set" });
                println!("  User SSH Key: {}", self.user_ssh_key.as_deref().unwrap_or("Will copy root key"));
                println!("  • Will keep root password authentication enabled");
                println!("  • New user gets sudo privileges without password");
            }
            SetupMode::Script => {
                println!("🚀 SCRIPT MODE:");
                println!("  SSH Key: {}", self.root_ssh_key.as_deref().unwrap_or("Not set"));
                println!("  Script Path: {}", self.script_path.as_deref().unwrap_or("Not set"));
                println!("  Script Args: {}", self.script_args.as_deref().unwrap_or("None"));
                println!("  • Will upload and run the specified script");
            }
        }
        
        println!();
        println!("📄 OUTPUT:");
        println!("  Info File: {}", self.info_file_path.as_deref().unwrap_or("./vps_setup_info.txt (default)"));
        println!();
        
        // Show setup readiness status
        println!("🚦 SETUP READINESS:");
        let missing_fields = self.get_missing_required_fields();
        if missing_fields.is_empty() {
            println!("  ✅ Ready! All required fields are configured.");
        } else {
            println!("  ❌ Missing: {}", missing_fields.join(", "));
        }
    }
    
    fn get_missing_required_fields(&self) -> Vec<String> {
        let mut missing = Vec::new();
        
        // Common requirements for all modes
        if self.username.is_none() {
            missing.push("username".to_string());
        }
        if self.ip.is_none() {
            missing.push("ip".to_string());
        }
        
        match self.mode {
            SetupMode::RootOnly => {
                // Root-only mode requires SSH key (will disable password auth)
                if self.root_ssh_key.is_none() {
                    missing.push("root_ssh_key".to_string());
                }
            }
            SetupMode::NewUser => {
                // New user mode needs either SSH key or password for initial connection
                if self.root_ssh_key.is_none() && self.password.is_none() {
                    missing.push("root_ssh_key or password".to_string());
                }
                // New user details
                if self.sudo_username.is_none() {
                    missing.push("sudo_username".to_string());
                }
                if self.sudo_password.is_none() {
                    missing.push("sudo_password".to_string());
                }
            }
            SetupMode::Script => {
                // Script mode needs connection method and script
                if self.root_ssh_key.is_none() && self.password.is_none() {
                    missing.push("root_ssh_key or password".to_string());
                }
                if self.script_path.is_none() {
                    missing.push("script_path".to_string());
                }
            }
        }
        
        missing
    }
    
    pub fn is_valid_for_connection(&self) -> bool {
        self.username.is_some() && self.ip.is_some()
    }
    
    pub fn is_valid_for_key_copy(&self) -> bool {
        self.username.is_some() && self.password.is_some() && self.ip.is_some() && self.root_ssh_key.is_some()
    }
        
    fn config_file_path() -> Result<PathBuf> {
        let home_dir = dirs::home_dir()
            .context("Failed to get home directory")?;
        
        Ok(home_dir.join(".config").join("autovps").join("config.json"))
    }
}