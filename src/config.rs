//! Cargo's global config and credentials files.
//!
//! Edits `$CARGO_HOME/config.toml` and `$CARGO_HOME/credentials.toml` in
//! place with `toml_edit`, so existing comments and formatting are preserved.

use anyhow::{Context, Result, anyhow};
use std::fs;
use std::path::{Path, PathBuf};
use toml_edit::{Array, DocumentMut, TableLike};
use zeroize::Zeroizing;

/// The provider name cargo resolves on `PATH`.
const PROVIDER: &str = "cargo-credential-fido";

fn cargo_home() -> Result<PathBuf> {
    if let Some(home) = std::env::var_os("CARGO_HOME") {
        return Ok(PathBuf::from(home));
    }
    let home = dirs::home_dir().ok_or_else(|| anyhow!("cannot determine home directory"))?;
    Ok(home.join(".cargo"))
}

/// The file cargo reads for `name`: `name.toml`, or the legacy
/// extensionless `name` if only that one exists.
fn cargo_file(name: &str) -> Result<PathBuf> {
    let home = cargo_home()?;
    let path = home.join(format!("{name}.toml"));
    let legacy = home.join(name);
    if !path.exists() && legacy.exists() {
        return Ok(legacy);
    }
    Ok(path)
}

/// Parse a TOML file, or return `None` if it does not exist.
fn read_doc(path: &Path) -> Result<Option<DocumentMut>> {
    // Zeroizing: this may be the credentials file.
    let text = match fs::read_to_string(path) {
        Ok(text) => Zeroizing::new(text),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e).with_context(|| format!("failed to read {}", path.display())),
    };
    text.parse()
        .map(Some)
        .with_context(|| format!("failed to parse {}", path.display()))
}

/// Whether this provider is listed in `registry.global-credential-providers`.
pub fn is_configured() -> Result<bool> {
    let Some(doc) = read_doc(&cargo_file("config")?)? else {
        return Ok(false);
    };
    Ok(doc
        .get("registry")
        .and_then(|r| r.get("global-credential-providers"))
        .and_then(|p| p.as_array())
        .is_some_and(|a| a.iter().any(|p| p.as_str() == Some(PROVIDER))))
}

/// Add this provider to `registry.global-credential-providers`.
pub fn configure() -> Result<()> {
    let path = cargo_file("config")?;
    let mut doc = read_doc(&path)?.unwrap_or_default();

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

/// A plaintext token found in cargo's credentials file.
pub struct PlainToken {
    /// The `[registries.NAME]` name, or `None` for crates.io (`[registry]`).
    pub name: Option<String>,
    /// The index URL cargo reports for this registry, if it could be found.
    pub index_url: Option<String>,
    pub token: Zeroizing<String>,
}

impl PlainToken {
    pub fn label(&self) -> &str {
        self.name.as_deref().unwrap_or("crates.io")
    }
}

/// Cargo's plaintext credentials file (`cargo:token`).
pub struct Credentials {
    path: PathBuf,
    doc: DocumentMut,
}

impl Credentials {
    /// Load the credentials file, or return `None` if there is none.
    pub fn load() -> Result<Option<Self>> {
        let path = cargo_file("credentials")?;
        Ok(read_doc(&path)?.map(|doc| Self { path, doc }))
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Every token in the file, with its index URL looked up in cargo's
    /// global config.
    pub fn tokens(&self, index_url: &str) -> Result<Vec<PlainToken>> {
        let config = read_doc(&cargo_file("config")?)?.unwrap_or_default();
        let mut tokens = Vec::new();
        if let Some(token) = token_in(self.doc.get("registry").and_then(|r| r.as_table_like())) {
            tokens.push(PlainToken {
                name: None,
                index_url: Some(index_url.to_string()),
                token,
            });
        }
        if let Some(registries) = self.doc.get("registries").and_then(|r| r.as_table_like()) {
            for (name, table) in registries.iter() {
                if let Some(token) = token_in(table.as_table_like()) {
                    tokens.push(PlainToken {
                        name: Some(name.to_string()),
                        index_url: registry_index(&config, name),
                        token,
                    });
                }
            }
        }
        Ok(tokens)
    }

    /// Remove the token for registry `name` (`None` for crates.io), and the
    /// tables left empty by it.
    pub fn remove(&mut self, name: Option<&str>) {
        let root = self.doc.as_table_mut();
        match name {
            None => remove_token(root, "registry"),
            Some(name) => {
                if let Some(registries) = root
                    .get_mut("registries")
                    .and_then(|r| r.as_table_like_mut())
                {
                    remove_token(registries, name);
                    if registries.is_empty() {
                        root.remove("registries");
                    }
                }
            }
        }
    }

    pub fn save(&self) -> Result<()> {
        // Writing in place keeps the file's existing permissions.
        fs::write(&self.path, Zeroizing::new(self.doc.to_string()).as_bytes())
            .with_context(|| format!("failed to write {}", self.path.display()))
    }
}

fn token_in(table: Option<&dyn TableLike>) -> Option<Zeroizing<String>> {
    let token = table?.get("token")?.as_str()?;
    Some(Zeroizing::new(token.to_string()))
}

/// Remove `parent.key.token`, then `parent.key` if that left it empty.
fn remove_token(parent: &mut dyn TableLike, key: &str) {
    if let Some(table) = parent.get_mut(key).and_then(|t| t.as_table_like_mut()) {
        table.remove("token");
        if table.is_empty() {
            parent.remove(key);
        }
    }
}

/// The index URL of registry `name`, as cargo would report it.
fn registry_index(config: &DocumentMut, name: &str) -> Option<String> {
    let var = format!(
        "CARGO_REGISTRIES_{}_INDEX",
        name.to_uppercase().replace('-', "_")
    );
    if let Ok(url) = std::env::var(var) {
        return Some(url);
    }
    let index = config.get("registries")?.get(name)?.get("index")?;
    index.as_str().map(String::from)
}

