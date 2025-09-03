use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

/// Expands a path that may contain ~ to the full home directory path
pub fn expand_home_dir<P: AsRef<Path>>(path: P) -> Result<PathBuf> {
    let path = path.as_ref();
    
    if let Some(path_str) = path.to_str() {
        if path_str.starts_with("~/") {
            let home_dir = dirs::home_dir()
                .context("Failed to get home directory")?;
            let expanded = home_dir.join(&path_str[2..]);
            return Ok(expanded);
        } else if path_str == "~" {
            let home_dir = dirs::home_dir()
                .context("Failed to get home directory")?;
            return Ok(home_dir);
        }
    }
    
    Ok(path.to_path_buf())
}

/// Validates that a file exists, expanding ~ if needed
pub fn validate_file_path<P: AsRef<Path>>(path: P) -> Result<PathBuf> {
    let path_ref = path.as_ref();
    let expanded_path = expand_home_dir(&path)?;
    
    if !expanded_path.exists() {
        return Err(anyhow::anyhow!(
            "File not found: {} (expanded to: {})", 
            path_ref.display(),
            expanded_path.display()
        ));
    }
    
    Ok(expanded_path)
}

/// Validates that a directory exists, expanding ~ if needed
pub fn validate_dir_path<P: AsRef<Path>>(path: P) -> Result<PathBuf> {
    let path_ref = path.as_ref();
    let expanded_path = expand_home_dir(&path)?;
    
    if let Some(parent) = expanded_path.parent() {
        if !parent.exists() {
            return Err(anyhow::anyhow!(
                "Directory not found: {} (expanded to: {})", 
                path_ref.display(),
                parent.display()
            ));
        }
    }
    
    Ok(expanded_path)
}