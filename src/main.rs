use clap::{Parser, Subcommand};
use anyhow::Result;

mod config;
mod ssh;
mod shell;
mod utils;

#[derive(Parser)]
#[command(name = "autovps")]
#[command(about = "A CLI tool for automatically setting up VPS configurations")]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    Interactive,
    Set {
        #[arg(short, long)]
        username: Option<String>,
        #[arg(short, long)]
        password: Option<String>,
        #[arg(short, long)]
        ip: Option<String>,
        #[arg(short, long)]
        ssh_key: Option<String>,
        #[arg(long)]
        sudo_username: Option<String>,
        #[arg(long)]
        sudo_password: Option<String>,
        #[arg(long)]
        info_file_path: Option<String>,
        #[arg(long)]
        keep_root_password: Option<bool>,
        #[arg(long)]
        use_root_ssh_key: Option<bool>,
        #[arg(long)]
        new_user_ssh_key: Option<String>,
    },
    Show,
    Connect,
    CopyKey,
    Setup,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Some(Commands::Interactive) | None => {
            shell::run_interactive_shell().await?;
        }
        Some(Commands::Set { username, password, ip, ssh_key, sudo_username, sudo_password, info_file_path, keep_root_password, use_root_ssh_key, new_user_ssh_key }) => {
            let mut config = config::Config::load()?;
            
            if let Some(username) = username {
                config.set_username(username);
            }
            if let Some(password) = password {
                config.set_password(password);
            }
            if let Some(ip) = ip {
                config.set_ip(ip);
            }
            if let Some(ssh_key) = ssh_key {
                if let Err(e) = config.set_ssh_key_path(ssh_key) {
                    println!("Error setting SSH key path: {}", e);
                    return Ok(());
                }
            }
            if let Some(sudo_username) = sudo_username {
                config.set_sudo_username(sudo_username);
            }
            if let Some(sudo_password) = sudo_password {
                config.set_sudo_password(sudo_password);
            }
            if let Some(info_file_path) = info_file_path {
                if let Err(e) = config.set_info_file_path(info_file_path) {
                    println!("Error setting info file path: {}", e);
                    return Ok(());
                }
            }
            if let Some(keep_root_password) = keep_root_password {
                config.set_keep_root_password(keep_root_password);
            }
            if let Some(use_root_ssh_key) = use_root_ssh_key {
                config.set_use_root_ssh_key(use_root_ssh_key);
            }
            if let Some(new_user_ssh_key) = new_user_ssh_key {
                if let Err(e) = config.set_new_user_ssh_key_path(new_user_ssh_key) {
                    println!("Error setting new user SSH key path: {}", e);
                    return Ok(());
                }
            }
            
            config.save()?;
            println!("Configuration updated successfully");
        }
        Some(Commands::Show) => {
            let config = config::Config::load()?;
            config.display();
        }
        Some(Commands::Connect) => {
            let config = config::Config::load()?;
            ssh::test_connection(&config).await?;
        }
        Some(Commands::CopyKey) => {
            let config = config::Config::load()?;
            ssh::copy_ssh_key(&config).await?;
        }
        Some(Commands::Setup) => {
            let config = config::Config::load()?;
            ssh::setup_vps(&config).await?;
        }
    }

    Ok(())
}
