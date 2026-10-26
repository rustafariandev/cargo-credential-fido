//! On-disk store of encrypted tokens.
//!
//! Each token is sealed with XChaCha20-Poly1305 under a key derived from the
//! FIDO key's hmac-secret output for a per-token random salt. The registry
//! index URL is bound in as associated data, so a ciphertext cannot be moved
//! to another registry entry.

use crate::fido::{Authenticator, random_bytes};
use anyhow::{Context, Result, anyhow};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use zeroize::Zeroizing;

const STORE_VERSION: u32 = 1;

#[derive(Serialize, Deserialize)]
pub struct Store {
    version: u32,
    pub credential: Option<CredentialRecord>,
    pub tokens: BTreeMap<String, SealedToken>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct CredentialRecord {
    #[serde(with = "hex")]
    pub id: Vec<u8>,
    /// Whether the credential was created (and must be used) with a PIN.
    pub uv: bool,
}

#[derive(Serialize, Deserialize)]
pub struct SealedToken {
    #[serde(with = "hex")]
    salt: [u8; 32],
    #[serde(with = "hex")]
    nonce: [u8; 24],
    #[serde(with = "hex")]
    ciphertext: Vec<u8>,
}

impl Default for Store {
    fn default() -> Self {
        Self {
            version: STORE_VERSION,
            credential: None,
            tokens: BTreeMap::new(),
        }
    }
}

pub fn path() -> Result<PathBuf> {
    if let Some(p) = std::env::var_os("CARGO_CREDENTIAL_FIDO_STORE") {
        return Ok(PathBuf::from(p));
    }
    let dir = dirs::config_dir().ok_or_else(|| anyhow!("cannot determine config directory"))?;
    Ok(dir.join("cargo-credential-fido").join("store.json"))
}

impl Store {
    pub fn load() -> Result<Self> {
        let path = path()?;
        match fs::read(&path) {
            Ok(bytes) => {
                let store: Store = serde_json::from_slice(&bytes)
                    .with_context(|| format!("corrupt store at {}", path.display()))?;
                if store.version != STORE_VERSION {
                    return Err(anyhow!("unsupported store version {}", store.version));
                }
                Ok(store)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Store::default()),
            Err(e) => Err(e).with_context(|| format!("failed to read {}", path.display())),
        }
    }

    /// Atomically write the store, readable only by the current user.
    pub fn save(&self) -> Result<()> {
        let path = path()?;
        let dir = path.parent().ok_or_else(|| anyhow!("invalid store path"))?;
        fs::create_dir_all(dir)?;

        let tmp = path.with_extension("json.tmp");
        let mut opts = fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut file = opts
            .open(&tmp)
            .with_context(|| format!("failed to write {}", tmp.display()))?;
        file.write_all(&serde_json::to_vec_pretty(self)?)?;
        file.sync_all()?;
        fs::rename(&tmp, &path)?;
        Ok(())
    }

    pub fn seal(
        &mut self,
        auth: &Authenticator,
        cred: &CredentialRecord,
        pin: Option<&str>,
        index_url: &str,
        token: &str,
    ) -> Result<()> {
        let salt = random_bytes::<32>();
        let nonce = random_bytes::<24>();
        let key = auth.derive_key(&cred.id, &salt, pin)?;
        let ciphertext = cipher(&key)
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: token.as_bytes(),
                    aad: index_url.as_bytes(),
                },
            )
            .map_err(|_| anyhow!("encryption failed"))?;
        self.tokens.insert(
            index_url.to_string(),
            SealedToken {
                salt,
                nonce,
                ciphertext,
            },
        );
        Ok(())
    }

    /// Decrypt the token for `index_url`. Returns `Ok(None)` if none is stored.
    pub fn unseal(
        &self,
        auth: &Authenticator,
        pin: Option<&str>,
        index_url: &str,
    ) -> Result<Option<Zeroizing<String>>> {
        let (Some(cred), Some(sealed)) = (&self.credential, self.tokens.get(index_url)) else {
            return Ok(None);
        };
        let key = auth.derive_key(&cred.id, &sealed.salt, pin)?;
        let plain = Zeroizing::new(
            cipher(&key)
                .decrypt(
                    XNonce::from_slice(&sealed.nonce),
                    Payload {
                        msg: &sealed.ciphertext,
                        aad: index_url.as_bytes(),
                    },
                )
                .map_err(|_| {
                    anyhow!("decryption failed: this token was sealed by a different FIDO key")
                })?,
        );
        let token = std::str::from_utf8(&plain).context("stored token is not UTF-8")?;
        Ok(Some(Zeroizing::new(token.to_string())))
    }
}

fn cipher(key: &[u8; 32]) -> XChaCha20Poly1305 {
    XChaCha20Poly1305::new(key.into())
}
