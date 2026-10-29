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
use std::path::{Path, PathBuf};
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
        self.save_to(&path()?)
    }

    fn save_to(&self, path: &Path) -> Result<()> {
        let dir = path.parent().ok_or_else(|| anyhow!("invalid store path"))?;
        fs::create_dir_all(dir)?;

        // The rename keeps the temporary file's permissions.
        let tmp = path.with_extension("json.tmp");
        let result = self.write_private(&tmp);
        if result.is_err() {
            let _ = fs::remove_file(&tmp);
        }
        result.with_context(|| format!("failed to write {}", tmp.display()))?;
        fs::rename(&tmp, path)?;
        Ok(())
    }

    fn write_private(&self, path: &Path) -> Result<()> {
        let mut file = crate::secure::create_private(path)?;
        file.write_all(&serde_json::to_vec_pretty(self)?)?;
        file.sync_all()?;
        // On Windows the file is opened unshared; dropping it here closes
        // it so it can be renamed.
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
            // The key's output differs with and without the PIN, so a PIN
            // mode mismatch looks the same as the wrong key.
            .map_err(|_| {
                anyhow!(
                    "decryption failed: this token was sealed by a different FIDO key, \
                     or the key now uses its PIN differently (for example after \
                     turning on alwaysUv; see the README)"
                )
            })?,
    );
    let token = std::str::from_utf8(&plain).context("stored token is not UTF-8")?;
    Ok(Zeroizing::new(token.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fido::fake::FakeAuthenticator;

    const URL: &str = "https://github.com/rust-lang/crates.io-index";
    const TOKEN: &str = "cio_secret_token";

    /// A store with `TOKEN` sealed for `URL` by `auth`.
    fn sealed(auth: &FakeAuthenticator) -> Store {
        let mut store = Store::default();
        let cred = auth.enroll().unwrap();
        store.seal(auth, &cred, URL, TOKEN).unwrap();
        store.credential = Some(cred);
        store
    }

    #[test]
    fn seal_then_unseal() {
        for has_pin in [false, true] {
            let auth = FakeAuthenticator::new(has_pin);
            let store = sealed(&auth);
            let token = store.unseal(&auth, URL).unwrap().unwrap();
            assert_eq!(token.as_str(), TOKEN);
            assert_eq!(auth.touches.get(), 2);
        }
    }

    #[test]
    fn ciphertext_hides_the_token() {
        let auth = FakeAuthenticator::new(false);
        let json = serde_json::to_string(&sealed(&auth)).unwrap();
        assert!(!json.contains(TOKEN));
    }

    #[test]
    fn each_seal_gets_a_fresh_salt_and_nonce() {
        let auth = FakeAuthenticator::new(false);
        let mut store = sealed(&auth);
        let cred = store.credential.clone().unwrap();
        store
            .seal(&auth, &cred, "sparse+https://other/", TOKEN)
            .unwrap();
        let (a, b) = (&store.tokens[URL], &store.tokens["sparse+https://other/"]);
        assert_ne!(a.salt, b.salt);
        assert_ne!(a.nonce, b.nonce);
    }

    #[test]
    fn unseal_unknown_registry_is_none() {
        let auth = FakeAuthenticator::new(false);
        let store = sealed(&auth);
        let touches = auth.touches.get();
        assert!(
            store
                .unseal(&auth, "sparse+https://other/")
                .unwrap()
                .is_none()
        );
        assert_eq!(auth.touches.get(), touches, "no touch for a missing token");
    }

    #[test]
    fn another_key_cannot_unseal() {
        let store = sealed(&FakeAuthenticator::new(false));
        assert!(store.unseal(&FakeAuthenticator::new(false), URL).is_err());
    }

    #[test]
    fn save_writes_a_private_file_and_can_overwrite_it() {
        let auth = FakeAuthenticator::new(false);
        let store = sealed(&auth);
        let dir = std::env::temp_dir().join(format!(
            "cargo-credential-fido-test-{}",
            hex::encode(random_bytes::<8>())
        ));
        let path = dir.join("store.json");

        store.save_to(&path).unwrap();
        store.save_to(&path).unwrap();
        let saved: Store = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        assert_eq!(saved.unseal(&auth, URL).unwrap().unwrap().as_str(), TOKEN);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        #[cfg(windows)]
        assert_eq!(
            crate::secure::file_dacl(&path).unwrap(),
            crate::secure::canonical_sddl(&crate::secure::file_sddl().unwrap()).unwrap()
        );
        fs::remove_dir_all(&dir).unwrap();
    }

    /// Needs a directory on a volume that stores no ACLs (FAT, exFAT) in
    /// `CARGO_CREDENTIAL_FIDO_TEST_NO_ACL_DIR`; CI mounts one on Windows.
    #[test]
    #[ignore]
    fn save_works_on_a_volume_without_acls() {
        let dir = std::env::var_os("CARGO_CREDENTIAL_FIDO_TEST_NO_ACL_DIR")
            .expect("CARGO_CREDENTIAL_FIDO_TEST_NO_ACL_DIR is not set");
        let dir = Path::new(&dir).join(format!(
            "cargo-credential-fido-test-{}",
            hex::encode(random_bytes::<8>())
        ));
        let path = dir.join("store.json");
        let auth = FakeAuthenticator::new(false);
        let store = sealed(&auth);

        store.save_to(&path).unwrap();
        store.save_to(&path).unwrap();
        let saved: Store = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        assert_eq!(saved.unseal(&auth, URL).unwrap().unwrap().as_str(), TOKEN);
        assert!(!path.with_extension("json.tmp").exists());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn pin_mode_must_match() {
        let auth = FakeAuthenticator::new(true);
        let mut store = sealed(&auth);
        store.credential.as_mut().unwrap().uv = false;
        let err = store.unseal(&auth, URL).unwrap_err();
        assert!(
            err.to_string().contains("uses its PIN differently"),
            "{err}"
        );
    }

    #[test]
    fn ciphertext_is_bound_to_its_registry() {
        let auth = FakeAuthenticator::new(false);
        let mut store = sealed(&auth);
        let moved = store.tokens.remove(URL).unwrap();
        store.tokens.insert("sparse+https://other/".into(), moved);
        assert!(store.unseal(&auth, "sparse+https://other/").is_err());
    }

    #[test]
    fn rotate_uses_one_touch_and_a_new_salt() {
        let auth = FakeAuthenticator::new(false);
        let mut store = sealed(&auth);
        let old_salt = store.tokens[URL].salt;
        let touches = auth.touches.get();

        store.rotate(&auth, URL).unwrap();
        assert_eq!(auth.touches.get(), touches + 1);
        assert_ne!(store.tokens[URL].salt, old_salt);
        assert_eq!(store.unseal(&auth, URL).unwrap().unwrap().as_str(), TOKEN);
    }

    #[test]
    fn failed_rotate_leaves_the_token() {
        let auth = FakeAuthenticator::new(false);
        let mut store = sealed(&auth);
        let old_salt = store.tokens[URL].salt;
        assert!(store.rotate(&FakeAuthenticator::new(false), URL).is_err());
        assert_eq!(store.tokens[URL].salt, old_salt);
        assert_eq!(store.unseal(&auth, URL).unwrap().unwrap().as_str(), TOKEN);
    }

    #[test]
    fn store_survives_json() {
        let auth = FakeAuthenticator::new(true);
        let json = serde_json::to_vec(&sealed(&auth)).unwrap();
        let store: Store = serde_json::from_slice(&json).unwrap();
        assert_eq!(store.unseal(&auth, URL).unwrap().unwrap().as_str(), TOKEN);
    }
}
