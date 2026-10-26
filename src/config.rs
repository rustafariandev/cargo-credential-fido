//! Registering this provider in cargo's global config.
//!
//! Edits `$CARGO_HOME/config.toml` in place with `toml_edit`, so existing
//! comments and formatting are preserved.

use anyhow::{Context, Result, anyhow};
use std::fs;
use std::path::PathBuf;
use toml_edit::{Array, DocumentMut};

/// The provider name cargo resolves on `PATH`.
const PROVIDER: &str = "cargo-credential-fido";

fn cargo_home() -> Result<PathBuf> {
    if let Some(home) = std::env::var_os("CARGO_HOME") {
        return Ok(PathBuf::from(home));
    }
    let home = dirs::home_dir().ok_or_else(|| anyhow!("cannot determine home directory"))?;
    Ok(home.join(".cargo"))
}

/// The config file cargo reads: `config.toml`, or the legacy extensionless
/// `config` if only that one exists.
fn config_path() -> Result<PathBuf> {
    let home = cargo_home()?;
    let path = home.join("config.toml");
    let legacy = home.join("config");
    if !path.exists() && legacy.exists() {
        return Ok(legacy);
    }
    Ok(path)
}

/// Add this provider to `registry.global-credential-providers`.
pub fn configure() -> Result<()> {
    let path = config_path()?;
    let text = match fs::read_to_string(&path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => return Err(e).with_context(|| format!("failed to read {}", path.display())),
    };
    let mut doc: DocumentMut = text
        .parse()
        .with_context(|| format!("failed to parse {}", path.display()))?;

    let registry = doc
        .entry("registry")
        .or_insert(toml_edit::table())
        .as_table_like_mut()
        .ok_or_else(|| anyhow!("`registry` in {} is not a table", path.display()))?;
    let providers = registry
        .entry("global-credential-providers")
        .or_insert(toml_edit::value(Array::new()))
        .as_array_mut()
        .ok_or_else(|| {
            anyhow!(
                "`registry.global-credential-providers` in {} is not an array",
                path.display()
            )
        })?;

    if providers.iter().any(|p| p.as_str() == Some(PROVIDER)) {
        eprintln!("{PROVIDER} is already configured in {}", path.display());
        return Ok(());
    }
    let others: Vec<String> = providers
        .iter()
        .filter_map(|p| p.as_str())
        .map(String::from)
        .collect();
    // Cargo prefers providers toward the end of the list.
    providers.push(PROVIDER);

    let dir = path
        .parent()
        .ok_or_else(|| anyhow!("invalid config path"))?;
    fs::create_dir_all(dir)?;
    fs::write(&path, doc.to_string())
        .with_context(|| format!("failed to write {}", path.display()))?;

    eprintln!(
        "Added {PROVIDER} to registry.global-credential-providers in {}",
        path.display()
    );
    if !others.is_empty() {
        eprintln!(
            "Other providers are still listed as fallbacks: {}",
            others.join(", ")
        );
    }
    Ok(())
}
