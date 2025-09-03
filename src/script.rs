use crate::config::Config;
use crate::ssh;
use anyhow::{anyhow, Context, Result};
use std::fs;
use std::path::Path;

pub async fn upload_and_run_script(config: &Config) -> Result<()> {
    if !config.is_valid_for_connection() {
        return Err(anyhow!("Configuration incomplete. Need at least username and IP address."));
    }

    let script_path = config.script_path.as_ref()
        .ok_or_else(|| anyhow!("No script path configured. Use 'set script_path <path>'"))?;
    
    if !Path::new(script_path).exists() {
        return Err(anyhow!("Script file not found: {}", script_path));
    }

    let username = config.username.as_ref().unwrap();
    let ip = config.ip.as_ref().unwrap();

    println!("🚀 Starting script deployment to {}@{}...", username, ip);
    println!("📋 Deployment Plan:");
    println!("   • Connect to server: {}@{}", username, ip);
    println!("   • Upload script: {}", script_path);
    if let Some(args) = &config.script_args {
        println!("   • Run with args: {}", args);
    } else {
        println!("   • Run with no arguments");
    }
    println!();

    // Step 1: Test connection
    println!("Step 1/3: Testing connection...");
    ssh::test_connection(config).await?;
    println!("   ✅ Connection successful");

    // Step 2: Upload script
    println!("Step 2/3: Uploading script...");
    upload_script_file(config, script_path).await?;
    println!("   ✅ Script uploaded successfully");

    // Step 3: Execute script
    println!("Step 3/3: Executing script...");
    let script_name = Path::new(script_path)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("script.sh");
    
    let remote_path = format!("/tmp/{}", script_name);
    let args = config.script_args.as_deref().unwrap_or("");
    let command = if args.is_empty() {
        format!("chmod +x {} && {}", remote_path, remote_path)
    } else {
        format!("chmod +x {} && {} {}", remote_path, remote_path, args)
    };

    let output = ssh::execute_command(config, &command).await?;
    
    println!("   ✅ Script execution completed");
    println!();
    println!("📋 SCRIPT OUTPUT:");
    println!("{}", if output.trim().is_empty() { "(no output)" } else { &output });
    
    // Clean up remote script
    let cleanup_command = format!("rm -f {}", remote_path);
    ssh::execute_command(config, &cleanup_command).await?;
    println!();
    println!("🎉 Script deployment completed successfully!");

    Ok(())
}

pub async fn upload_script_file(config: &Config, local_path: &str) -> Result<()> {
    let script_content = fs::read_to_string(local_path)
        .context("Failed to read script file")?;

    let script_name = Path::new(local_path)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("script.sh");
    
    let remote_path = format!("/tmp/{}", script_name);
    
    // Create the script file on remote server
    let create_command = format!("cat > {} << 'AUTOVPS_SCRIPT_EOF'\n{}\nAUTOVPS_SCRIPT_EOF", 
                                remote_path, script_content);
    
    ssh::execute_command(config, &create_command).await?;
    
    Ok(())
}

pub async fn list_remote_scripts(config: &Config) -> Result<()> {
    println!("📋 Listing scripts in /tmp directory...");
    let output = ssh::execute_command(config, "ls -la /tmp/*.sh 2>/dev/null || echo 'No shell scripts found in /tmp'").await?;
    println!("{}", output);
    Ok(())
}

pub async fn run_remote_command(config: &Config, command: &str) -> Result<()> {
    if !config.is_valid_for_connection() {
        return Err(anyhow!("Configuration incomplete. Need at least username and IP address."));
    }

    let username = config.username.as_ref().unwrap();
    let ip = config.ip.as_ref().unwrap();

    println!("🔧 Executing command on {}@{}: {}", username, ip, command);
    
    let output = ssh::execute_command(config, command).await?;
    
    if !output.trim().is_empty() {
        println!("📋 OUTPUT:");
        println!("{}", output);
    } else {
        println!("📋 Command completed with no output");
    }
    
    Ok(())
}