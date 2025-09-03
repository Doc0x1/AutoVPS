use clap::{Parser, Subcommand};
use anyhow::Result;

mod config;
mod ssh;
mod shell;
mod script;
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
        mode: Option<String>,
        #[arg(long)]
        root_ssh_key: Option<String>,
        #[arg(long)]
        user_ssh_key: Option<String>,
        #[arg(long)]
        sudo_username: Option<String>,
        #[arg(long)]
        sudo_password: Option<String>,
        #[arg(long)]
        script_path: Option<String>,
        #[arg(long)]
        script_args: Option<String>,
        #[arg(long)]
        info_file_path: Option<String>,
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
        Some(Commands::Set { username, password, ip, mode, root_ssh_key, user_ssh_key, sudo_username, sudo_password, script_path, script_args, info_file_path }) => {
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
            if let Some(mode) = mode {
                if let Err(e) = config.set_mode(&mode) {
                    println!("Error setting mode: {}", e);
                    return Ok(());
                }
            }
            if let Some(root_ssh_key) = root_ssh_key {
                if let Err(e) = config.set_root_ssh_key(root_ssh_key) {
                    println!("Error setting root SSH key path: {}", e);
                    return Ok(());
                }
            }
            if let Some(user_ssh_key) = user_ssh_key {
                if let Err(e) = config.set_user_ssh_key(user_ssh_key) {
                    println!("Error setting user SSH key path: {}", e);
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
            if let Some(script_path) = script_path {
                if let Err(e) = config.set_script_path(script_path) {
                    println!("Error setting script path: {}", e);
                    return Ok(());
                }
            }
            if let Some(script_args) = script_args {
                config.set_script_args(script_args);
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
