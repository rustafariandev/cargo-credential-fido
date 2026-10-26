//! A software authenticator for tests, so the code above the trait can run
//! without a FIDO key on every OS.
//!
//! It behaves like a real key where the store relies on it: outputs depend
//! on the key's secret, the salt and whether a PIN was used, and the key
//! rejects credentials it did not create.

use super::{Authenticator, Credential, Key, new_key, random_bytes};
use anyhow::{Result, bail};
use sha2::{Digest, Sha256};
use std::cell::Cell;

pub struct FakeAuthenticator {
    secret: [u8; 32],
    id: Vec<u8>,
    has_pin: bool,
    /// Number of assertions, i.e. touches.
    pub touches: Cell<u32>,
}

impl FakeAuthenticator {
    pub fn new(has_pin: bool) -> Self {
        Self {
            secret: random_bytes(),
            id: random_bytes::<16>().to_vec(),
            has_pin,
            touches: Cell::new(0),
        }
    }

    fn output(&self, cred: &Credential, salt: &[u8; 32]) -> Key {
        // Real keys keep separate secrets with and without user
        // verification; mixing `uv` in models that.
        let digest: [u8; 32] = Sha256::new()
            .chain_update(self.secret)
            .chain_update([cred.uv as u8])
            .chain_update(salt)
            .finalize()
            .into();
        new_key(&digest)
    }

    fn assert(&self, cred: &Credential) -> Result<()> {
        if cred.id != self.id {
            bail!("FIDO key assertion failed (wrong key or wrong PIN?)");
        }
        self.touches.set(self.touches.get() + 1);
        Ok(())
    }
}

impl Authenticator for FakeAuthenticator {
    fn enroll(&self) -> Result<Credential> {
        Ok(Credential {
            id: self.id.clone(),
            uv: self.has_pin,
        })
    }

    fn derive_key(&self, cred: &Credential, salt: &[u8; 32]) -> Result<Key> {
        self.assert(cred)?;
        Ok(self.output(cred, salt))
    }

    fn derive_key_pair(
        &self,
        cred: &Credential,
        salt1: &[u8; 32],
        salt2: &[u8; 32],
    ) -> Result<(Key, Key)> {
        self.assert(cred)?;
        Ok((self.output(cred, salt1), self.output(cred, salt2)))
    }
}
