//! On-disk store of encrypted tokens.
//!
//! Each token is sealed with XChaCha20-Poly1305 under a key derived from the
//! FIDO key's hmac-secret output for a per-token random salt. The registry
//! index URL is bound in as associated data, so a ciphertext cannot be moved
//! to another registry entry.

use crate::fido::{Authenticator, Credential, random_bytes};
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
    pub credential: Option<Credential>,
    pub tokens: BTreeMap<String, SealedToken>,
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
        auth: &dyn Authenticator,
        cred: &Credential,
        index_url: &str,
        token: &str,
    ) -> Result<()> {
        let salt = random_bytes::<32>();
        let key = auth.derive_key(cred, &salt)?;
        let sealed = encrypt(&key, salt, index_url, token)?;
        self.tokens.insert(index_url.to_string(), sealed);
        Ok(())
    }

    /// Decrypt the token for `index_url`. Returns `Ok(None)` if none is stored.
    pub fn unseal(
        &self,
        auth: &dyn Authenticator,
        index_url: &str,
    ) -> Result<Option<Zeroizing<String>>> {
        let (Some(cred), Some(sealed)) = (&self.credential, self.tokens.get(index_url)) else {
            return Ok(None);
        };
        let key = auth.derive_key(cred, &sealed.salt)?;
        decrypt(&key, sealed, index_url).map(Some)
    }

    /// Re-encrypt the token for `index_url` under a fresh salt and nonce.
    ///
    /// Both the old and the new key come from a single assertion, using the
    /// two-salt form of hmac-secret, so this needs only one touch.
    pub fn rotate(&mut self, auth: &dyn Authenticator, index_url: &str) -> Result<()> {
        let (Some(cred), Some(sealed)) = (&self.credential, self.tokens.get(index_url)) else {
            return Err(anyhow!("no token stored for {index_url}"));
        };
        let new_salt = random_bytes::<32>();
        let (old_key, new_key) = auth.derive_key_pair(cred, &sealed.salt, &new_salt)?;
        let token = decrypt(&old_key, sealed, index_url)?;
        let resealed = encrypt(&new_key, new_salt, index_url, &token)?;
        self.tokens.insert(index_url.to_string(), resealed);
        Ok(())
    }
}

fn cipher(key: &[u8; 32]) -> XChaCha20Poly1305 {
    XChaCha20Poly1305::new(key.into())
}

fn encrypt(key: &[u8; 32], salt: [u8; 32], index_url: &str, token: &str) -> Result<SealedToken> {
    let nonce = random_bytes::<24>();
    let ciphertext = cipher(key)
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: token.as_bytes(),
                aad: index_url.as_bytes(),
            },
        )
        .map_err(|_| anyhow!("encryption failed"))?;
    Ok(SealedToken {
        salt,
        nonce,
        ciphertext,
    })
}

fn decrypt(key: &[u8; 32], sealed: &SealedToken, index_url: &str) -> Result<Zeroizing<String>> {
    let plain = Zeroizing::new(
        cipher(key)
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
    Ok(Zeroizing::new(token.to_string()))
}
