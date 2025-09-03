use crate::{config::Config, ssh};
use anyhow::Result;
use rustyline::{error::ReadlineError, completion::{FilenameCompleter, Completer, Pair}, hint::HistoryHinter, highlight::MatchingBracketHighlighter, validate::MatchingBracketValidator, Editor, CompletionType, Config as RustylineConfig, EditMode};
use rustyline::history::FileHistory;
use std::borrow::Cow::{self, Borrowed, Owned};

struct MyHelper {
    completer: FilenameCompleter,
    highlighter: MatchingBracketHighlighter,
    validator: MatchingBracketValidator,
    hinter: HistoryHinter,
}

impl rustyline::Helper for MyHelper {}

impl Completer for MyHelper {
    type Candidate = Pair;

    fn complete(
        &self,
        line: &str,
        pos: usize,
        _ctx: &rustyline::Context<'_>,
    ) -> rustyline::Result<(usize, Vec<Self::Candidate>)> {
        // Check if we're setting a path-related option
        if line.starts_with("set ") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                let option = parts[1];
                if matches!(option, "ssh_key" | "info_file_path" | "new_user_ssh_key") {
                    // Use filename completion for path options
                    return self.completer.complete(line, pos, _ctx);
                }
            }
        }
        
        // Default to command completion
        let commands = vec![
            "help", "show", "info", "set", "unset", "connect", "test", 
            "test_key", "copy_key", "copykey", "setup", "run", "exec", 
            "clear", "exit", "quit"
        ];

        let start = line.rfind(' ').map_or(0, |i| i + 1);
        let prefix = &line[start..pos];
        
        let matches: Vec<Pair> = commands
            .into_iter()
            .filter(|cmd| cmd.starts_with(prefix))
            .map(|cmd| Pair {
                display: cmd.to_string(),
                replacement: cmd.to_string(),
            })
            .collect();
            
        Ok((start, matches))
    }
}

impl rustyline::highlight::Highlighter for MyHelper {
    fn highlight_prompt<'b, 's: 'b, 'p: 'b>(
        &'s self,
        prompt: &'p str,
        default: bool,
    ) -> Cow<'b, str> {
        if default {
            Borrowed(&prompt[..])
        } else {
            Borrowed(&prompt[..])
        }
    }

    fn highlight_hint<'h>(&self, hint: &'h str) -> Cow<'h, str> {
        Owned("\x1b[1m".to_owned() + hint + "\x1b[m")
    }

    fn highlight<'l>(&self, line: &'l str, pos: usize) -> Cow<'l, str> {
        self.highlighter.highlight(line, pos)
    }

    fn highlight_char(&self, line: &str, pos: usize, forced: bool) -> bool {
        self.highlighter.highlight_char(line, pos, forced)
    }
}

impl rustyline::hint::Hinter for MyHelper {
    type Hint = String;

    fn hint(&self, line: &str, pos: usize, ctx: &rustyline::Context<'_>) -> Option<String> {
        self.hinter.hint(line, pos, ctx)
    }
}

impl rustyline::validate::Validator for MyHelper {
    fn validate(
        &self,
        ctx: &mut rustyline::validate::ValidationContext,
    ) -> rustyline::Result<rustyline::validate::ValidationResult> {
        self.validator.validate(ctx)
    }

    fn validate_while_typing(&self) -> bool {
        self.validator.validate_while_typing()
    }
}

pub async fn run_interactive_shell() -> Result<()> {
    let config = RustylineConfig::builder()
        .history_ignore_space(true)
        .completion_type(CompletionType::List)
        .edit_mode(EditMode::Emacs)
        .build();
    
    let helper = MyHelper {
        completer: FilenameCompleter::new(),
        highlighter: MatchingBracketHighlighter::new(),
        validator: MatchingBracketValidator::new(),
        hinter: HistoryHinter {},
    };
    
    let mut rl: Editor<MyHelper, FileHistory> = Editor::with_config(config)?;
    rl.set_helper(Some(helper));
    let mut config = Config::load()?;
    
    println!("AutoVPS Interactive Shell");
    println!("Type 'help' for available commands or 'exit' to quit");
    println!();
    
    config.display();
    println!();

    loop {
        let readline = rl.readline("AutoVPS> ");
        
        match readline {
            Ok(line) => {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }
                
                rl.add_history_entry(line)?;
                
                if let Err(e) = handle_command(&mut config, line).await {
                    println!("Error: {}", e);
                }
            }
            Err(ReadlineError::Interrupted) => {
                println!("^C");
                continue;
            }
            Err(ReadlineError::Eof) => {
                println!("exit");
                break;
            }
            Err(err) => {
                println!("Error: {:?}", err);
                break;
            }
        }
    }
    
    Ok(())
}

async fn handle_command(config: &mut Config, input: &str) -> Result<()> {
    let parts: Vec<&str> = input.split_whitespace().collect();
    if parts.is_empty() {
        return Ok(());
    }

    let command = parts[0].to_lowercase();
    let args = &parts[1..];

    match command.as_str() {
        "help" | "?" => show_help(),
        "exit" | "quit" => std::process::exit(0),
        "show" | "info" => {
            config.display();
        }
        "set" => {
            if args.is_empty() {
                println!("Usage: set <option> [value]");
                println!("Options: username, password, ip, ssh_key, sudo_username, sudo_password, info_file_path, keep_root_password, use_root_ssh_key, new_user_ssh_key");
                println!("Note: 'password' and 'sudo_password' will prompt for secure input (no value needed)");
                return Ok(());
            }
            
            // For password fields, don't require a value argument
            if args.len() < 2 && !matches!(args[0].to_lowercase().as_str(), "password" | "sudo_password") {
                println!("Usage: set <option> <value>");
                println!("Options: username, password, ip, ssh_key, sudo_username, sudo_password, info_file_path, keep_root_password, use_root_ssh_key, new_user_ssh_key");
                println!("Note: 'password' and 'sudo_password' will prompt for secure input (no value needed)");
                return Ok(());
            }
            
            let option = args[0].to_lowercase();
            let value = if args.len() > 1 { args[1..].join(" ") } else { String::new() };
            
            match option.as_str() {
                "username" => {
                    config.set_username(value.clone());
                    println!("Username set to: {}", value);
                }
                "password" => {
                    println!("Enter password for root user:");
                    match rpassword::read_password() {
                        Ok(password) => {
                            config.set_password(password);
                            println!("Password set");
                        }
                        Err(e) => {
                            println!("Error reading password: {}", e);
                            return Ok(());
                        }
                    }
                }
                "ip" => {
                    config.set_ip(value.clone());
                    println!("IP address set to: {}", value);
                }
                "ssh_key" => {
                    match config.set_ssh_key_path(value.clone()) {
                        Ok(_) => println!("SSH key path set to: {}", value),
                        Err(e) => {
                            println!("Error setting SSH key path: {}", e);
                            return Ok(());
                        }
                    }
                }
                "sudo_username" => {
                    config.set_sudo_username(value.clone());
                    println!("Sudo username set to: {}", value);
                }
                "sudo_password" => {
                    println!("Enter password for new user:");
                    match rpassword::read_password() {
                        Ok(password) => {
                            config.set_sudo_password(password);
                            println!("Sudo password set");
                        }
                        Err(e) => {
                            println!("Error reading password: {}", e);
                            return Ok(());
                        }
                    }
                }
                "info_file_path" => {
                    match config.set_info_file_path(value.clone()) {
                        Ok(_) => println!("Info file path set to: {}", value),
                        Err(e) => {
                            println!("Error setting info file path: {}", e);
                            return Ok(());
                        }
                    }
                }
                "keep_root_password" => {
                    match value.to_lowercase().as_str() {
                        "true" | "yes" | "1" | "on" => {
                            config.set_keep_root_password(true);
                            println!("Root password authentication will be kept enabled");
                        }
                        "false" | "no" | "0" | "off" => {
                            config.set_keep_root_password(false);
                            println!("Root password authentication will be disabled");
                        }
                        _ => {
                            println!("Invalid value. Use: true/false, yes/no, 1/0, or on/off");
                            return Ok(());
                        }
                    }
                }
                "use_root_ssh_key" => {
                    match value.to_lowercase().as_str() {
                        "true" | "yes" | "1" | "on" => {
                            config.set_use_root_ssh_key(true);
                            println!("Root SSH key authentication enabled");
                        }
                        "false" | "no" | "0" | "off" => {
                            config.set_use_root_ssh_key(false);
                            println!("Root SSH key authentication disabled (password only)");
                        }
                        _ => {
                            println!("Invalid value. Use: true/false, yes/no, 1/0, or on/off");
                            return Ok(());
                        }
                    }
                }
                "new_user_ssh_key" => {
                    match config.set_new_user_ssh_key_path(value.clone()) {
                        Ok(_) => println!("New user SSH key path set to: {}", value),
                        Err(e) => {
                            println!("Error setting new user SSH key path: {}", e);
                            return Ok(());
                        }
                    }
                }
                _ => {
                    println!("Unknown option: {}. Available options: username, password, ip, ssh_key, sudo_username, sudo_password, info_file_path, keep_root_password, use_root_ssh_key, new_user_ssh_key", option);
                }
            }
            
            config.save()?;
        }
        "unset" => {
            if args.is_empty() {
                println!("Usage: unset <option>");
                println!("Options: username, password, ip, ssh_key, sudo_username, sudo_password, info_file_path, keep_root_password, use_root_ssh_key, new_user_ssh_key");
                return Ok(());
            }
            
            let option = args[0].to_lowercase();
            match option.as_str() {
                "username" => {
                    config.username = None;
                    println!("Username unset");
                }
                "password" => {
                    config.password = None;
                    println!("Password unset");
                }
                "ip" => {
                    config.ip = None;
                    println!("IP address unset");
                }
                "ssh_key" => {
                    config.ssh_key_path = None;
                    println!("SSH key path unset");
                }
                "sudo_username" => {
                    config.sudo_username = None;
                    println!("Sudo username unset");
                }
                "sudo_password" => {
                    config.sudo_password = None;
                    println!("Sudo password unset");
                }
                "info_file_path" => {
                    config.info_file_path = None;
                    println!("Info file path unset");
                }
                "keep_root_password" => {
                    config.keep_root_password = true; // Reset to default
                    println!("Keep root password reset to default (enabled)");
                }
                "use_root_ssh_key" => {
                    config.use_root_ssh_key = true; // Reset to default
                    println!("Use root SSH key reset to default (enabled)");
                }
                "new_user_ssh_key" => {
                    config.new_user_ssh_key_path = None;
                    println!("New user SSH key path unset");
                }
                _ => {
                    println!("Unknown option: {}. Available options: username, password, ip, ssh_key, sudo_username, sudo_password, info_file_path, keep_root_password, use_root_ssh_key, new_user_ssh_key", option);
                }
            }
            
            config.save()?;
        }
        "connect" | "test" => {
            println!("Testing connection...");
            ssh::test_connection(config).await?;
        }
        "test_key" => {
            println!("Testing SSH key authentication...");
            match ssh::test_ssh_key_auth(config).await {
                Ok(_) => println!("✅ SSH key authentication successful!"),
                Err(e) => println!("❌ SSH key authentication failed: {}", e),
            }
        }
        "copy_key" | "copykey" => {
            println!("Copying SSH key...");
            ssh::copy_ssh_key(config).await?;
        }
        "setup" => {
            println!("Starting full VPS setup...");
            ssh::setup_vps(config).await?;
        }
        "run" | "exec" => {
            if args.is_empty() {
                println!("Usage: run <command>");
                return Ok(());
            }
            
            let command = args.join(" ");
            println!("Executing: {}", command);
            
            match ssh::execute_command(config, &command).await {
                Ok(output) => {
                    if !output.trim().is_empty() {
                        println!("{}", output);
                    }
                }
                Err(e) => {
                    println!("Command failed: {}", e);
                }
            }
        }
        "clear" => {
            print!("\x1B[2J\x1B[1;1H");
        }
        _ => {
            println!("Unknown command: {}. Type 'help' for available commands.", command);
        }
    }
    
    Ok(())
}

fn show_help() {
    let help_text = r#"
AutoVPS - Automated VPS Setup Tool

🎯 PURPOSE: Transform a fresh VPS with root password access into a secure server 
           with SSH key authentication and a dedicated user account.

Available Commands:
  help, ?                Show this help message
  show, info             Display current configuration
  set <option> <value>   Set configuration option
  unset <option>         Unset configuration option
  connect, test          Test SSH connection to configured server
  test_key               Test SSH key authentication only
  copy_key, copykey      Copy SSH public key to root user (requires root password)
  setup                  🚀 Complete VPS setup (recommended - does everything needed)
  run, exec <command>    Execute command on remote server
  clear                  Clear the screen
  exit, quit             Exit the interactive shell

📋 SETUP PROCESS EXPLAINED:

  🔐 INITIAL CONNECTION CREDENTIALS (for connecting to VPS):
    username             Root username (typically 'root')
    password             Root password (secure input - just type 'set password')
    ip                   Server IP address
    ssh_key              Path to your SSH private key file (~/ expansion supported)

  👤 NEW USER TO CREATE (will be created during setup):
    sudo_username        Username for NEW user to create
    sudo_password        Password for NEW user (secure input - just type 'set sudo_password')
    new_user_ssh_key     SSH key for NEW user (optional, defaults to copying root's key)

  🔧 SECURITY & CONNECTION SETTINGS:
    use_root_ssh_key     Try SSH key first for root connection (true/false, default: true)
    keep_root_password   Keep root password authentication (true/false, default: true)
    info_file_path       Where to save setup info (~/ expansion supported)

🔄 What 'setup' command does:
  1. Tests connection based on use_root_ssh_key setting
  2. If SSH key fails or disabled, uses password to copy SSH key to server
  3. Creates NEW user with sudo_username/sudo_password
  4. Gives NEW user sudo privileges (no password required for sudo)
  5. Copies SSH key to NEW user (custom key or root's key)
  6. Configures root password authentication based on keep_root_password setting
  7. Generates detailed info file with connection instructions

💡 FLEXIBLE CONNECTION & SECURITY OPTIONS:
  • use_root_ssh_key=true (DEFAULT): Try SSH key first, fallback to password
  • use_root_ssh_key=false: Use password only for connection (for fresh VPS)
  • keep_root_password=true (DEFAULT): Root can use SSH key + password
  • keep_root_password=false: Root can only use SSH key (more secure)
  • new_user_ssh_key: Set separate SSH key for new user, or defaults to copying root's

🎯 RESULT: 
  • Root: SSH key + password OR SSH key only (based on keep_root_password setting)
  • NEW User: SSH key + password access + full sudo without prompts
  • Flexible, production-ready server setup

📝 Example Setups:

🔸 Fresh VPS (no SSH key setup yet):
  set username root                    # Connect as root initially  
  set password                         # Enter root password securely (hidden input)
  set use_root_ssh_key false          # Use password only for fresh VPS
  set ip 192.168.1.100                # Your VPS IP
  set ssh_key ~/.ssh/id_rsa           # Your SSH key (will be copied)
  set sudo_username deployuser        # NEW user to create
  set sudo_password                   # Enter NEW user password securely (hidden input)
  setup                               # Run complete setup

🔸 Existing VPS (SSH key already there):
  set username root                    # Connect as root
  set use_root_ssh_key true           # Try SSH key first (default)
  set ip 192.168.1.100                # Your VPS IP
  set ssh_key ~/.ssh/id_rsa           # Your existing SSH key
  set sudo_username deployuser        # NEW user to create
  set sudo_password                   # Enter NEW user password securely (hidden input)
  set new_user_ssh_key ~/.ssh/deploy_key  # Different key for new user
  set keep_root_password false        # Disable root password (more secure)
  setup                               # Run complete setup

💡 TIP: Use 'show' command to see your configuration before running 'setup'
"#;
    println!("{}", help_text);
}