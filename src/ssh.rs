use crate::config::Config;
use anyhow::{anyhow, Context, Result};
use ssh2::Session;
use std::fs;
use std::io::prelude::*;
use std::net::TcpStream;
use std::path::Path;
use tokio::task;

pub async fn test_connection(config: &Config) -> Result<()> {
    if !config.is_valid_for_connection() {
        return Err(anyhow!("Configuration incomplete. Need at least username and IP address."));
    }

    let username = config.username.as_ref().unwrap();
    let ip = config.ip.as_ref().unwrap();

    println!("Testing connection to {}@{}...", username, ip);

    let username = username.clone();
    let ip = ip.clone();
    let ssh_key_path = config.ssh_key_path.clone();
    let password = config.password.clone();

    task::spawn_blocking(move || {
        let tcp = TcpStream::connect(format!("{}:22", ip))
            .context("Failed to connect to SSH server")?;

        let mut sess = Session::new()?;
        sess.set_tcp_stream(tcp);
        sess.handshake()?;

        if let Some(key_path) = ssh_key_path {
            if Path::new(&key_path).exists() {
                sess.userauth_pubkey_file(&username, None, Path::new(&key_path), None)?;
            } else {
                return Err(anyhow!("SSH key file not found: {}", key_path));
            }
        } else if let Some(pass) = password {
            sess.userauth_password(&username, &pass)?;
        } else {
            return Err(anyhow!("No authentication method available (need SSH key or password)"));
        }

        if !sess.authenticated() {
            return Err(anyhow!("Authentication failed"));
        }

        println!("✓ Successfully connected to {}@{}", username, ip);
        Ok::<(), anyhow::Error>(())
    })
    .await??;

    Ok(())
}

pub async fn copy_ssh_key(config: &Config) -> Result<()> {
    if !config.is_valid_for_key_copy() {
        return Err(anyhow!(
            "Configuration incomplete. Need username, password, IP address, and SSH key path."
        ));
    }

    let username = config.username.as_ref().unwrap();
    let password = config.password.as_ref().unwrap();
    let ip = config.ip.as_ref().unwrap();
    let ssh_key_path = config.ssh_key_path.as_ref().unwrap();

    if !Path::new(ssh_key_path).exists() {
        return Err(anyhow!("SSH key file not found: {}", ssh_key_path));
    }

    let public_key_path = format!("{}.pub", ssh_key_path);
    if !Path::new(&public_key_path).exists() {
        return Err(anyhow!("Public key file not found: {}", public_key_path));
    }

    let public_key = fs::read_to_string(&public_key_path)
        .context("Failed to read public key file")?;

    println!("Copying SSH key to {}@{}...", username, ip);

    let username = username.clone();
    let password = password.clone();
    let ip = ip.clone();
    let public_key = public_key.trim().to_string();

    task::spawn_blocking(move || {
        let tcp = TcpStream::connect(format!("{}:22", ip))
            .context("Failed to connect to SSH server")?;

        let mut sess = Session::new()?;
        sess.set_tcp_stream(tcp);
        sess.handshake()?;

        sess.userauth_password(&username, &password)?;

        if !sess.authenticated() {
            return Err(anyhow!("Authentication failed"));
        }

        // Create SSH directory and set permissions
        let mut channel = sess.channel_session()?;
        channel.exec("mkdir -p ~/.ssh && chmod 700 ~/.ssh")?;
        
        // Wait for command to complete and get exit status
        channel.wait_eof()?;
        let exit_status = channel.exit_status()?;
        channel.close()?;
        channel.wait_close()?;
        
        if exit_status != 0 {
            return Err(anyhow!("Failed to create SSH directory (exit status: {})", exit_status));
        }

        // Add SSH key to authorized_keys
        let mut channel = sess.channel_session()?;
        let command = format!(
            "echo '{}' >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys && sort -u ~/.ssh/authorized_keys -o ~/.ssh/authorized_keys",
            public_key
        );
        channel.exec(&command)?;
        
        // Wait for command to complete and get exit status
        channel.wait_eof()?;
        let exit_status = channel.exit_status()?;
        channel.close()?;
        channel.wait_close()?;
        
        if exit_status != 0 {
            return Err(anyhow!("Failed to copy SSH key (exit status: {})", exit_status));
        }

        println!("✓ SSH key successfully copied to {}@{}", username, ip);
        Ok::<(), anyhow::Error>(())
    })
    .await??;

    Ok(())
}

pub async fn execute_command(config: &Config, command: &str) -> Result<String> {
    if !config.is_valid_for_connection() {
        return Err(anyhow!("Configuration incomplete. Need at least username and IP address."));
    }

    let username = config.username.as_ref().unwrap();
    let ip = config.ip.as_ref().unwrap();
    let ssh_key_path = config.ssh_key_path.clone();
    let password = config.password.clone();

    let username = username.clone();
    let ip = ip.clone();
    let command = command.to_string();

    let output = task::spawn_blocking(move || {
        let tcp = TcpStream::connect(format!("{}:22", ip))
            .context("Failed to connect to SSH server")?;

        let mut sess = Session::new()?;
        sess.set_tcp_stream(tcp);
        sess.handshake()?;

        if let Some(key_path) = ssh_key_path {
            if Path::new(&key_path).exists() {
                sess.userauth_pubkey_file(&username, None, Path::new(&key_path), None)?;
            } else {
                return Err(anyhow!("SSH key file not found: {}", key_path));
            }
        } else if let Some(pass) = password {
            sess.userauth_password(&username, &pass)?;
        } else {
            return Err(anyhow!("No authentication method available"));
        }

        if !sess.authenticated() {
            return Err(anyhow!("Authentication failed"));
        }

        let mut channel = sess.channel_session()?;
        channel.exec(&command)?;

        let mut output = String::new();
        channel.read_to_string(&mut output)?;
        
        // Properly close the channel
        channel.wait_eof()?;
        channel.close()?;
        channel.wait_close()?;

        Ok::<String, anyhow::Error>(output)
    })
    .await??;

    Ok(output)
}

pub async fn setup_vps(config: &Config) -> Result<()> {
    if !config.is_valid_for_connection() {
        return Err(anyhow!(
            "Configuration incomplete. Need username, IP address, and SSH key path."
        ));
    }

    if config.sudo_username.is_none() || config.sudo_password.is_none() {
        return Err(anyhow!(
            "Configuration incomplete. Need sudo_username and sudo_password to create new user."
        ));
    }

    let username = config.username.as_ref().unwrap();
    let ip = config.ip.as_ref().unwrap();
    let sudo_username = config.sudo_username.as_ref().unwrap();

    println!("🚀 Starting VPS setup for {}@{}...", username, ip);
    println!("📋 Setup Plan:");
    println!("   • Connect using credentials for: {}@{}", username, ip);  
    println!("   • Create NEW user: '{}'", sudo_username);
    println!("   • Grant '{}' sudo privileges (no password required)", sudo_username);
    if config.keep_root_password {
        println!("   • Keep root password authentication enabled");
    } else {
        println!("   • Disable root password authentication (SSH key only)");
    }
    println!();
    
    // Step 1: Test connection and optionally copy SSH key
    println!("Step 1/4: Checking connection and SSH key setup...");
    let _ssh_key_needed = check_and_setup_ssh_key(config).await?;
    
    // Step 2: Create new sudo user
    println!("Step 2/4: Creating new sudo user '{}'...", sudo_username);
    create_sudo_user(config).await?;
    
    // Step 3: Harden SSH config (disable root password login)
    println!("Step 3/4: Hardening SSH configuration (disabling root password login)...");
    harden_ssh_config(config).await?;
    
    // Step 4: Generate info file
    println!("Step 4/4: Generating setup information file...");
    generate_info_file(config).await?;
    
    println!("🎉 VPS setup completed successfully!");
    println!();
    println!("✅ SETUP SUMMARY:");
    if config.keep_root_password {
        println!("   • Root user: SSH key + password access (both enabled)");
    } else {
        println!("   • Root user: SSH key access only (password disabled)");
    }
    println!("   • New user '{}': SSH key + password access + sudo privileges", sudo_username);
    println!("   • Server is now configured and production-ready!");
    println!();
    println!("🔗 Next steps: Check the info file for connection details");
    
    Ok(())
}

pub async fn check_and_setup_ssh_key(config: &Config) -> Result<bool> {
    let _username = config.username.as_ref().unwrap();
    let _ip = config.ip.as_ref().unwrap();

    // If root SSH key usage is disabled, skip SSH key test and go straight to password
    if !config.use_root_ssh_key {
        println!("   ⚠️  Root SSH key authentication disabled, using password only");
        if config.password.is_none() {
            return Err(anyhow!(
                "Root SSH key disabled but no password provided. Set password: set password <password>"
            ));
        }
        println!("   📋 Copying SSH key using password authentication...");
        copy_ssh_key(config).await?;
        println!("   ✅ SSH key copied successfully!");
        return Ok(true);
    }

    println!("   🔍 Testing SSH key authentication...");
    
    // First try SSH key authentication if enabled
    match test_ssh_key_auth(config).await {
        Ok(_) => {
            println!("   ✅ SSH key authentication already works!");
            return Ok(false); // No SSH key copy needed
        }
        Err(_) => {
            println!("   ❌ SSH key authentication failed, will use password to copy key");
        }
    }

    // If SSH key auth failed, try password and copy key
    if config.password.is_none() {
        return Err(anyhow!(
            "SSH key authentication failed and no password provided. Either:\n  1. Set a password to copy SSH key: set password <password>\n  2. Manually copy your SSH key to the server first"
        ));
    }

    println!("   📋 Copying SSH key using password authentication...");
    copy_ssh_key(config).await?;
    println!("   ✅ SSH key copied successfully!");
    
    Ok(true) // SSH key was copied
}

pub async fn test_ssh_key_auth(config: &Config) -> Result<()> {
    if !config.is_valid_for_connection() {
        return Err(anyhow!("Configuration incomplete. Need at least username, IP, and SSH key path."));
    }

    let username = config.username.as_ref().unwrap();
    let ip = config.ip.as_ref().unwrap();
    let ssh_key_path = config.ssh_key_path.as_ref().unwrap();

    let username = username.clone();
    let ip = ip.clone();
    let ssh_key_path = ssh_key_path.clone();

    task::spawn_blocking(move || {
        let tcp = TcpStream::connect(format!("{}:22", ip))
            .context("Failed to connect to SSH server")?;

        let mut sess = Session::new()?;
        sess.set_tcp_stream(tcp);
        sess.handshake()?;

        if !Path::new(&ssh_key_path).exists() {
            return Err(anyhow!("SSH key file not found: {}", ssh_key_path));
        }

        sess.userauth_pubkey_file(&username, None, Path::new(&ssh_key_path), None)?;

        if !sess.authenticated() {
            return Err(anyhow!("SSH key authentication failed"));
        }

        Ok::<(), anyhow::Error>(())
    })
    .await??;

    Ok(())
}

pub async fn create_sudo_user(config: &Config) -> Result<()> {
    let sudo_username = config.sudo_username.as_ref().unwrap();
    let sudo_password = config.sudo_password.as_ref().unwrap();

    let commands = vec![
        format!("useradd -m -s /bin/bash {}", sudo_username),
        format!("echo '{}:{}' | chpasswd", sudo_username, sudo_password),
        format!("usermod -aG sudo {}", sudo_username),
        format!("echo '{} ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/{}", sudo_username, sudo_username),
        format!("chmod 440 /etc/sudoers.d/{}", sudo_username),
    ];

    for command in commands {
        let output = execute_command(config, &command).await?;
        if !output.trim().is_empty() {
            println!("Command output: {}", output);
        }
    }

    // Setup SSH key for the new user
    setup_new_user_ssh_key(config, sudo_username).await?;

    println!("✓ Sudo user '{}' created successfully", sudo_username);
    Ok(())
}

pub async fn setup_new_user_ssh_key(config: &Config, sudo_username: &str) -> Result<()> {
    // Create SSH directory for new user with proper ownership and permissions
    println!("   🔧 Setting up SSH directory with proper ownership and permissions");
    
    let setup_commands = vec![
        format!("mkdir -p /home/{}/.ssh", sudo_username),
        format!("chown {}:{} /home/{}/.ssh", sudo_username, sudo_username, sudo_username),
        format!("chmod 700 /home/{}/.ssh", sudo_username),
    ];

    for command in &setup_commands {
        execute_command(config, command).await?;
    }

    // Determine which SSH key to use for the new user
    if let Some(new_user_key_path) = &config.new_user_ssh_key_path {
        // Use the specific SSH key for the new user
        println!("   📋 Copying new user's SSH key: {}", new_user_key_path);
        
        let public_key_path = format!("{}.pub", new_user_key_path);
        if !std::path::Path::new(&public_key_path).exists() {
            return Err(anyhow!("New user's public key file not found: {}", public_key_path));
        }

        let public_key = std::fs::read_to_string(&public_key_path)
            .context("Failed to read new user's public key file")?;

        let key_commands = vec![
            format!("echo '{}' >> /home/{}/.ssh/authorized_keys", public_key.trim(), sudo_username),
            format!("chown {}:{} /home/{}/.ssh/authorized_keys", sudo_username, sudo_username, sudo_username),
            format!("chmod 600 /home/{}/.ssh/authorized_keys", sudo_username),
        ];
        
        for command in &key_commands {
            execute_command(config, command).await?;
        }
        
        println!("   ✅ New user's SSH key copied successfully");
    } else {
        // Copy root's SSH key to the new user
        println!("   📋 Copying root's SSH key to new user");
        
        let copy_commands = vec![
            format!("cp /root/.ssh/authorized_keys /home/{}/.ssh/", sudo_username),
            format!("chown {}:{} /home/{}/.ssh/authorized_keys", sudo_username, sudo_username, sudo_username),
            format!("chmod 600 /home/{}/.ssh/authorized_keys", sudo_username),
        ];

        for command in &copy_commands {
            execute_command(config, command).await?;
        }
        
        println!("   ✅ Root's SSH key copied to new user");
    }

    // Final verification: Ensure all permissions and ownership are correct
    let final_setup_commands = vec![
        format!("chown -R {}:{} /home/{}/.ssh", sudo_username, sudo_username, sudo_username),
        format!("chmod 700 /home/{}/.ssh", sudo_username),
        format!("chmod 600 /home/{}/.ssh/authorized_keys", sudo_username),
        format!("ls -la /home/{}/.ssh/", sudo_username), // Verify ownership
    ];

    println!("   🔍 Final verification of SSH directory ownership and permissions");
    for command in &final_setup_commands {
        let output = execute_command(config, command).await?;
        if command.contains("ls -la") && !output.trim().is_empty() {
            println!("   📋 SSH directory listing:\n{}", output);
        }
    }

    println!("   ✅ SSH directory ownership and permissions verified");
    Ok(())
}

pub async fn harden_ssh_config(config: &Config) -> Result<()> {
    let mut commands = vec![
        "cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup".to_string(),
        "sed -i 's/#PubkeyAuthentication yes/PubkeyAuthentication yes/' /etc/ssh/sshd_config".to_string(),
    ];

    if config.keep_root_password {
        // Allow root password login but ensure SSH keys are also enabled
        commands.extend(vec![
            "sed -i 's/#PermitRootLogin yes/PermitRootLogin yes/' /etc/ssh/sshd_config".to_string(),
            "sed -i 's/PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config".to_string(),
            "sed -i 's/#PasswordAuthentication no/PasswordAuthentication yes/' /etc/ssh/sshd_config".to_string(),
            "sed -i 's/PasswordAuthentication no/PasswordAuthentication yes/' /etc/ssh/sshd_config".to_string(),
        ]);
        println!("✓ SSH configured: Root can use both SSH key AND password authentication");
    } else {
        // Disable root password login (SSH key only)
        commands.extend(vec![
            "sed -i 's/#PermitRootLogin yes/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config".to_string(),
            "sed -i 's/PermitRootLogin yes/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config".to_string(),
            "sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config".to_string(),
            "sed -i 's/PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config".to_string(),
        ]);
        println!("✓ SSH configured: Root can ONLY use SSH key authentication (password disabled)");
    }

    commands.push("systemctl restart sshd".to_string());

    for command in &commands {
        execute_command(config, command).await?;
    }

    println!("✓ SSH configuration hardened successfully");
    Ok(())
}

pub async fn generate_info_file(config: &Config) -> Result<()> {
    use chrono::{DateTime, Utc};
    use std::fs;

    let info_path = if let Some(path) = &config.info_file_path {
        path.clone()
    } else {
        "./vps_setup_info.txt".to_string()
    };

    let now: DateTime<Utc> = Utc::now();
    let info_content = format!(
        r#"VPS Setup Information
======================
Setup Date: {}
Server IP: {}
Root Username: {}
New User Created: {} (with sudo privileges)

SSH Configuration:
- Root password login: {}
- Public key authentication: ENABLED  
- SSH Key Path: {}

Connection Instructions:
1. Connect as root:
   {}

2. Connect as new user (key-based auth):
   ssh -i {} {}@{}

3. Run commands with sudo (no password required):
   sudo <command>

User Information:
- New user '{}' was created with password authentication
- New user has sudo privileges without password prompt
- New user can also use SSH key authentication
- Root authentication: {}

Security Notes:
- Public key authentication is enabled for root
- New user can run sudo commands without entering password
- SSH configuration backup saved at /etc/ssh/sshd_config.backup

Generated by autovps
"#,
        now.format("%Y-%m-%d %H:%M:%S UTC"),
        config.ip.as_ref().unwrap(),
        config.username.as_ref().unwrap(),
        config.sudo_username.as_ref().unwrap(),
        if config.keep_root_password { "ENABLED" } else { "DISABLED" },
        config.ssh_key_path.as_ref().unwrap(),
        if config.keep_root_password { 
            format!("SSH key: ssh -i {} {}@{}\n   Password: ssh {}@{}", 
                config.ssh_key_path.as_ref().unwrap(),
                config.username.as_ref().unwrap(),
                config.ip.as_ref().unwrap(),
                config.username.as_ref().unwrap(),
                config.ip.as_ref().unwrap()) 
        } else { 
            format!("ssh -i {} {}@{} (SSH key only)", 
                config.ssh_key_path.as_ref().unwrap(),
                config.username.as_ref().unwrap(),
                config.ip.as_ref().unwrap()) 
        },
        config.ssh_key_path.as_ref().unwrap(),
        config.sudo_username.as_ref().unwrap(),
        config.ip.as_ref().unwrap(),
        config.sudo_username.as_ref().unwrap(),
        if config.keep_root_password { "SSH key + password enabled" } else { "SSH key only (password disabled)" },
    );

    fs::write(&info_path, info_content)
        .context("Failed to write info file")?;

    println!("✓ Setup information saved to: {}", info_path);
    Ok(())
}