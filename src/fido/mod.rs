//! Talking to the FIDO2 authenticator.
//!
//! The authenticator never sees the cargo token. We create one non-resident
//! credential with the `hmac-secret` extension, then for each stored token ask
//! the key for HMAC(credRandom, salt). That 32-byte output is the encryption
//! key: it can only be reproduced by this physical key, with a touch.
//!
//! How the key is reached depends on the OS:
//! - Linux and macOS talk CTAP2 to the key directly over HID (`hid`).
//! - Windows only lets elevated processes open FIDO keys as HID devices, so
//!   there we go through the system WebAuthn API (`windows`), which shows its
//!   own dialog for the PIN and the touch.

use anyhow::Result;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

#[cfg(not(windows))]
mod hid;
#[cfg(windows)]
mod windows;

/// Relying-party id the credential is scoped to. It never leaves the machine.
pub const RP_ID: &str = "cargo-credential-fido";

/// A 32-byte hmac-secret output, used directly as an encryption key.
///
/// Boxed so that moving a key only moves a pointer: moving the array itself
/// would leave stale copies of the secret on the stack.
pub type Key = Box<Zeroizing<[u8; 32]>>;

fn new_key(secret: &[u8; 32]) -> Key {
    let mut key = Box::new(Zeroizing::new([0u8; 32]));
    key.copy_from_slice(secret);
    key
}

/// The credential registered on the key, as kept in the store.
#[derive(Serialize, Deserialize, Clone)]
pub struct Credential {
    #[serde(with = "hex")]
    pub id: Vec<u8>,
    /// Whether the credential was created (and must be used) with a PIN.
    pub uv: bool,
    /// Whether store salts are WebAuthn PRF inputs rather than raw
    /// hmac-secret salts. See [`prf_salt`]. Credentials enrolled before
    /// Windows support use raw salts.
    #[serde(default)]
    pub prf: bool,
}

/// A FIDO2 key that can derive hmac-secret outputs.
///
/// The authenticator returns a different secret depending on whether user
/// verification (PIN) was performed, so every derivation uses `cred.uv`.
/// Implementations ask for the PIN themselves, if they need to.
pub trait Authenticator {
    /// Create a new hmac-secret credential. Uses a PIN if the key has one.
    fn enroll(&self) -> Result<Credential>;

    /// Derive the 32-byte secret for `salt` from the credential.
    fn derive_key(&self, cred: &Credential, salt: &[u8; 32]) -> Result<Key>;

    /// Derive the secrets for two salts at once, with a single touch.
    ///
    /// This is the two-salt form of hmac-secret, meant for key rotation:
    /// `salt1` gives the current key and `salt2` the next one.
    fn derive_key_pair(
        &self,
        cred: &Credential,
        salt1: &[u8; 32],
        salt2: &[u8; 32],
    ) -> Result<(Key, Key)>;
}

/// Open the plugged-in FIDO key with this platform's backend.
pub fn open() -> Result<Box<dyn Authenticator>> {
    #[cfg(not(windows))]
    return Ok(Box::new(hid::HidAuthenticator::open()?));
    #[cfg(windows)]
    return Ok(Box::new(windows::WebAuthnAuthenticator::open()?));
}

/// The hmac-secret salt the WebAuthn PRF extension sends for `input`.
///
/// Windows does not let ordinary processes pass raw hmac-secret salts: it
/// treats them as PRF inputs and hashes them like this before they reach the
/// key. Doing the same over HID gives the same secrets on every platform.
#[cfg_attr(windows, allow(dead_code))]
pub fn prf_salt(input: &[u8; 32]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"WebAuthn PRF\0");
    hash.update(input);
    hash.finalize().into()
}

pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut buf = [0u8; N];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prf_salt_matches_webauthn() {
        // SHA-256("WebAuthn PRF" || 0x00 || 32 zero bytes).
        assert_eq!(
            hex::encode(prf_salt(&[0u8; 32])),
            "4f24c9221e0ed3b764b4558a0d880ecea08117d62f2bdc13ae2c6c3ea662e3a1"
        );
    }

    #[test]
    fn old_credentials_use_raw_salts() {
        let cred: Credential = serde_json::from_str(r#"{"id":"0102","uv":false}"#).unwrap();
        assert!(!cred.prf);
    }
}
