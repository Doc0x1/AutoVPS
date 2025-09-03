# AutoVPS

A CLI tool for automatically setting up VPS configurations with SSH key authentication and user management.

## DISCLAIMER

This project is still in development and may be a bit confusing to use at this point in time. I recommend using the help command and reading to understand how things work.

## Overview

AutoVPS is designed to transform a fresh VPS with root password access into a secure server with SSH key authentication and a dedicated user account. It provides an interactive shell similar to msfconsole for configuring and managing VPS setup.

## Features

- 🔐 **Secure Password Input**: Masked password entry for sensitive credentials
- 🖥️ **Interactive Shell**: Easy-to-use command interface with tab completion
- 🔑 **SSH Key Management**: Automatic SSH key copying and configuration
- 👤 **User Creation**: Creates new users with sudo privileges
- 🛡️ **Security Hardening**: Configurable SSH security settings
- 📁 **Path Completion**: Tab completion for file and directory paths
- 📄 **Setup Reports**: Generates detailed setup information files

## Installation

### Prerequisites

- Rust (1.70.0 or later)
- OpenSSL development libraries

On Ubuntu/Debian:
```bash
sudo apt install -y libssl-dev pkg-config
```

### Building from Source

```bash
git clone https://github.com/Doc0x1/AutoVPS.git
cd AutoVPS
cargo build --release
```

## Usage

### Interactive Mode

Run the tool in interactive mode:
```bash
cargo run
# or after building
./target/release/AutoVPS
```

### Basic Setup Example

```bash
AutoVPS> set username root
AutoVPS> set password              # Secure masked input
AutoVPS> set ip 192.168.1.100
AutoVPS> set ssh_key ~/.ssh/id_rsa
AutoVPS> set sudo_username admin
AutoVPS> set sudo_password         # Secure masked input
AutoVPS> setup                     # Run complete setup
```

### Command Line Mode

You can also use command line arguments:
```bash
cargo run -- set --username root --ip 192.168.1.100
cargo run -- show
cargo run -- setup
```

## Configuration Options

### Initial Connection Credentials
- **username**: Root username (typically 'root')
- **password**: Root password (secure masked input)
- **ip**: Server IP address
- **ssh_key**: Path to your SSH private key file

### New User Settings
- **sudo_username**: Username for new user to create
- **sudo_password**: Password for new user (secure masked input)
- **new_user_ssh_key**: Optional separate SSH key for new user

### Security Settings
- **use_root_ssh_key**: Try SSH key first for root connection (default: true)
- **keep_root_password**: Keep root password authentication (default: true)
- **info_file_path**: Where to save setup information

## Commands

- `help` - Show available commands
- `show` / `info` - Display current configuration
- `set <option> [value]` - Set configuration option
- `unset <option>` - Unset configuration option
- `connect` / `test` - Test SSH connection
- `test_key` - Test SSH key authentication only
- `copy_key` - Copy SSH key to server
- `setup` - Run complete VPS setup
- `run <command>` - Execute command on remote server
- `clear` - Clear the screen
- `exit` / `quit` - Exit the shell

## Setup Process

The `setup` command performs these steps:

1. **Connection Test**: Verifies SSH connectivity
2. **SSH Key Setup**: Copies SSH key if needed using password authentication
3. **User Creation**: Creates new user with sudo privileges (no password required for sudo)
4. **SSH Configuration**: Sets up SSH keys for new user
5. **Security Hardening**: Configures SSH settings based on preferences
6. **Documentation**: Generates setup information file

## Security Features

- **Flexible Authentication**: Supports SSH key + password or SSH key only
- **Sudo Configuration**: Uses `/etc/sudoers.d/` for clean user management
- **SSH Hardening**: Configurable root password authentication
- **Secure Input**: Masked password entry prevents shoulder surfing
- **Key Management**: Proper file ownership and permissions for SSH keys

## Configuration Examples

### Fresh VPS Setup
```bash
set username root                    # Connect as root initially  
set password                         # Enter root password securely
set use_root_ssh_key false          # Use password for fresh VPS
set ip 192.168.1.100                # Your VPS IP
set ssh_key ~/.ssh/id_rsa           # Your SSH key (will be copied)
set sudo_username deployuser        # NEW user to create
set sudo_password                   # Enter NEW user password securely
setup                               # Run complete setup
```

### Existing VPS with SSH Key
```bash
set username root                    # Connect as root
set use_root_ssh_key true           # Try SSH key first (default)
set ip 192.168.1.100                # Your VPS IP
set ssh_key ~/.ssh/id_rsa           # Your existing SSH key
set sudo_username deployuser        # NEW user to create
set sudo_password                   # Enter NEW user password securely
set keep_root_password false        # Disable root password (more secure)
setup                               # Run complete setup
```

## Cleanup Commands

To remove a created user and cleanup:
```bash
# On the VPS as root:
sudo userdel -r username
sudo rm -f /etc/sudoers.d/username
```

## File Locations

- **Configuration**: `~/.config/autovps/config.json`
- **SSH Keys**: User-specified paths (with `~/` expansion)
- **Setup Info**: Configurable output location
- **Sudoers**: `/etc/sudoers.d/{username}` (individual files)

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

For issues, questions, or contributions, please open an issue on the repository.