//! Cargo's global config and credentials files.
//!
//! Edits `$CARGO_HOME/config.toml` and `$CARGO_HOME/credentials.toml` in
//! place with `toml_edit`, so existing comments and formatting are preserved.

use anyhow::{Context, Result, anyhow};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use toml_edit::{Array, DocumentMut, Table, TableLike};
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

/// The file cargo reads for `name`: the legacy extensionless `name` if it
/// exists, otherwise `name.toml`. Cargo prefers the legacy file even when
/// both exist.
fn cargo_file(name: &str) -> Result<PathBuf> {
    let home = cargo_home()?;
    let legacy = home.join(name);
    if legacy.is_file() {
        return Ok(legacy);
    }
    Ok(home.join(format!("{name}.toml")))
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
    // When the key is unset cargo uses `["cargo:token"]`. Keep that as a
    // fallback, so tokens still in the credentials file keep working.
    let providers = registry
        .entry("global-credential-providers")
        .or_insert(toml_edit::value(Array::from_iter(["cargo:token"])))
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
    write_atomic(&path, doc.to_string().as_bytes())?;

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
        let removed = match name {
            None => remove_token(root, "registry"),
            Some(name) => {
                let Some(registries) = root
                    .get_mut("registries")
                    .and_then(|r| r.as_table_like_mut())
                else {
                    return;
                };
                let removed = remove_token(registries, name);
                if registries.is_empty() {
                    root.remove("registries");
                }
                removed
            }
        };
        if let Some(comments) = removed {
            keep_comments(&mut self.doc, comments);
        }
    }

    pub fn save(&self) -> Result<()> {
        write_atomic(&self.path, Zeroizing::new(self.doc.to_string()).as_bytes())
    }
}

/// Replace `path` with `contents` through a temporary file and a rename, so
/// an interrupted write never leaves it truncated. The file keeps its
/// permissions (new files get 0600), and a symlink is followed rather than
/// replaced.
fn write_atomic(path: &Path, contents: &[u8]) -> Result<()> {
    let existing = fs::metadata(path).ok();
    let path = match existing {
        Some(_) => fs::canonicalize(path)
            .with_context(|| format!("failed to resolve {}", path.display()))?,
        None => path.to_path_buf(),
    };
    let mut name = path
        .file_name()
        .ok_or_else(|| anyhow!("{} is not a file path", path.display()))?
        .to_os_string();
    name.push(".tmp");
    let tmp = path.with_file_name(name);

    let mut opts = fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let write = || -> std::io::Result<()> {
        // A stale temporary file would keep its old permissions.
        match fs::remove_file(&tmp) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(e),
            _ => {}
        }
        let mut file = opts.open(&tmp)?;
        if let Some(meta) = &existing {
            file.set_permissions(meta.permissions())?;
        }
        file.write_all(contents)?;
        file.sync_all()?;
        fs::rename(&tmp, &path)
    };
    write().map_err(|e| {
        let _ = fs::remove_file(&tmp);
        anyhow::Error::new(e).context(format!("failed to write {}", path.display()))
    })
}

fn token_in(table: Option<&dyn TableLike>) -> Option<Zeroizing<String>> {
    let token = table?.get("token")?.as_str()?;
    Some(Zeroizing::new(token.to_string()))
}

/// Comments written above a table header that was removed, and where that
/// header was in the file.
struct Comments {
    position: isize,
    text: String,
}

/// Remove `parent.key.token`, then `parent.key` if that left it empty.
/// Returns the comments above `parent.key`'s header if it was removed, since
/// toml_edit removes them along with the table.
fn remove_token(parent: &mut dyn TableLike, key: &str) -> Option<Comments> {
    let table = parent.get_mut(key)?.as_table_like_mut()?;
    table.remove("token");
    if !table.is_empty() {
        return None;
    }
    let removed = parent.remove(key)?;
    let table = removed.as_table()?;
    let text = table.decor().prefix()?.as_str()?;
    if !text.contains('#') {
        return None;
    }
    Some(Comments {
        position: table.position()?,
        text: text.to_string(),
    })
}

/// Put `comments` above the table header that now follows where they were,
/// or at the end of the file if there is none.
fn keep_comments(doc: &mut DocumentMut, comments: Comments) {
    let next = next_header(doc.as_table(), comments.position);
    if let Some(table) = next.and_then(|p| header_at(doc.as_table_mut(), p)) {
        let prefix = table
            .decor()
            .prefix()
            .and_then(|p| p.as_str())
            .unwrap_or("");
        let prefix = format!("{}{prefix}", comments.text);
        table.decor_mut().set_prefix(prefix);
    } else {
        let trailing = doc.trailing().as_str().unwrap_or("").to_string();
        doc.set_trailing(format!("{trailing}{}", comments.text));
    }
}

/// The position of the first table header after `after`, at any depth.
fn next_header(table: &Table, after: isize) -> Option<isize> {
    table
        .iter()
        .filter_map(|(_, item)| item.as_table())
        .flat_map(|t| {
            let own = t.position().filter(|&p| p > after && !t.is_implicit());
            own.into_iter().chain(next_header(t, after))
        })
        .min()
}

/// The table whose header is at `position`, at any depth.
fn header_at(table: &mut Table, position: isize) -> Option<&mut Table> {
    for (_, item) in table.iter_mut() {
        let Some(t) = item.as_table_mut() else {
            continue;
        };
        if t.position() == Some(position) && !t.is_implicit() {
            return Some(t);
        }
        if let Some(found) = header_at(t, position) {
            return Some(found);
        }
    }
    None
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Remove the tokens of `names` from `text`, as `migrate` does.
    fn remove(text: &str, names: &[Option<&str>]) -> String {
        let mut creds = Credentials {
            path: PathBuf::new(),
            doc: text.parse().unwrap(),
        };
        for name in names {
            creds.remove(*name);
        }
        creds.doc.to_string()
    }

    #[test]
    fn comments_move_to_the_next_table() {
        let text =
            "# credentials\n[registry]\ntoken = \"a\"\n\n# bar\n[registries.bar]\ntoken = \"b\"\n";
        assert_eq!(
            remove(text, &[None]),
            "# credentials\n\n# bar\n[registries.bar]\ntoken = \"b\"\n"
        );
    }

    #[test]
    fn comments_of_a_nested_table_move_to_its_sibling() {
        let text =
            "# foo\n[registries.foo]\ntoken = \"a\"\n\n# bar\n[registries.bar]\ntoken = \"b\"\n";
        assert_eq!(
            remove(text, &[Some("foo")]),
            "# foo\n\n# bar\n[registries.bar]\ntoken = \"b\"\n"
        );
    }

    #[test]
    fn comments_of_the_last_table_move_to_the_end() {
        let text = "[registries.bar]\ntoken = \"b\"\n\n# crates.io\n[registry]\ntoken = \"a\"\n";
        assert_eq!(
            remove(text, &[None]),
            "[registries.bar]\ntoken = \"b\"\n\n# crates.io\n"
        );
    }

    #[test]
    fn tables_with_other_keys_are_kept() {
        let text = "# crates.io\n[registry]\ntoken = \"a\"\ndefault = \"x\"\n";
        assert_eq!(
            remove(text, &[None]),
            "# crates.io\n[registry]\ndefault = \"x\"\n"
        );
    }

    #[test]
    fn everything_removed_keeps_the_comments() {
        let text = "# credentials\n[registry]\ntoken = \"a\"\n\n[registries.foo]\ntoken = \"b\"\n";
        assert_eq!(remove(text, &[None, Some("foo")]), "# credentials\n\n");
    }
}
