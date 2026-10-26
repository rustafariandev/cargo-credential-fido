//! Talking to the FIDO2 authenticator.
//!
//! The authenticator never sees the cargo token. We create one non-resident
//! credential with the `hmac-secret` extension, then for each stored token ask
//! the key for HMAC(credRandom, salt). That 32-byte output is the encryption
//! key: it can only be reproduced by this physical key, with a touch.

use anyhow::{Context, Result, anyhow, bail};
use ctap_hid_fido2::fidokey::get_assertion::get_assertion_params::Assertion;
use ctap_hid_fido2::fidokey::get_info::InfoOption;
use ctap_hid_fido2::fidokey::{
    AssertionExtension, GetAssertionArgsBuilder, MakeCredentialArgsBuilder,
    make_credential::Extension as MakeExtension,
};
use ctap_hid_fido2::{FidoKeyHid, FidoKeyHidFactory, LibCfg};
use rand::RngCore;
use zeroize::{Zeroize, Zeroizing};

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

/// Wipe every hmac-secret output from the assertions once we have copied
/// out what we need.
fn wipe(assertions: &mut [Assertion]) {
    for ext in assertions.iter_mut().flat_map(|a| a.extensions.iter_mut()) {
        match ext {
            AssertionExtension::HmacSecret(Some(secret)) => secret.zeroize(),
            AssertionExtension::HmacSecret2(Some((a, b))) => {
                a.zeroize();
                b.zeroize();
            }
            _ => {}
        }
    }
}

pub struct Authenticator {
    device: FidoKeyHid,
}

impl Authenticator {
    pub fn open() -> Result<Self> {
        // stdout carries the cargo credential protocol, so keep-alive
        // ("touch your key") messages must go to stderr.
        let mut cfg = LibCfg::init().with_keep_alive_msg_to_stderr(true);
        cfg.keep_alive_msg = "Touch your FIDO key to continue...".to_string();
        let device = FidoKeyHidFactory::create(&cfg)
            .context("could not open FIDO key (is exactly one key plugged in?)")?;
        Ok(Self { device })
    }

    /// Whether the key has a PIN configured.
    pub fn has_pin(&self) -> Result<bool> {
        Ok(self.device.enable_info_option(&InfoOption::ClientPin)? == Some(true))
    }

    /// Create a new hmac-secret credential and return its credential id.
    pub fn enroll(&self, pin: Option<&str>) -> Result<Vec<u8>> {
        let support = self.device.get_info()?.extensions;
        if !support.iter().any(|e| e == "hmac-secret") {
            bail!("this FIDO key does not support the hmac-secret extension");
        }

        let challenge = random_bytes::<32>();
        let builder = MakeCredentialArgsBuilder::new(RP_ID, &challenge)
            .extensions(&[MakeExtension::HmacSecret(Some(true))]);
        let builder = match pin {
            Some(pin) => builder.pin(pin),
            None => builder.without_pin_and_uv(),
        };

        eprintln!("Registering a new credential on your FIDO key.");
        let att = self
            .device
            .make_credential_with_args(&builder.build())
            .context("FIDO key refused to create a credential")?;

        let hmac_enabled = att
            .extensions
            .iter()
            .any(|e| matches!(e, MakeExtension::HmacSecret(Some(true))));
        if !hmac_enabled {
            bail!("FIDO key did not enable hmac-secret for the new credential");
        }
        Ok(att.credential_descriptor.id)
    }

    /// Derive the 32-byte secret for `salt` from the credential.
    ///
    /// The authenticator returns a different secret depending on whether user
    /// verification (PIN) was performed, so `pin` must match how the entry
    /// was created.
    pub fn derive_key(
        &self,
        credential_id: &[u8],
        salt: &[u8; 32],
        pin: Option<&str>,
    ) -> Result<Key> {
        let mut assertions = self.hmac_secret(
            credential_id,
            AssertionExtension::HmacSecret(Some(*salt)),
            pin,
        )?;
        let key = extensions(&assertions).find_map(|e| match e {
            AssertionExtension::HmacSecret(Some(secret)) => Some(new_key(secret)),
            _ => None,
        });
        wipe(&mut assertions);
        key.ok_or_else(|| anyhow!("FIDO key did not return an hmac-secret"))
    }

    /// Derive the secrets for two salts at once, with a single touch.
    ///
    /// This is the two-salt form of hmac-secret, meant for key rotation:
    /// `salt1` gives the current key and `salt2` the next one.
    pub fn derive_key_pair(
        &self,
        credential_id: &[u8],
        salt1: &[u8; 32],
        salt2: &[u8; 32],
        pin: Option<&str>,
    ) -> Result<(Key, Key)> {
        let ext = AssertionExtension::HmacSecret2(Some((*salt1, *salt2)));
        let mut assertions = self.hmac_secret(credential_id, ext, pin)?;
        let keys = extensions(&assertions).find_map(|e| match e {
            AssertionExtension::HmacSecret2(Some((a, b))) => Some((new_key(a), new_key(b))),
            _ => None,
        });
        wipe(&mut assertions);
        keys.ok_or_else(|| anyhow!("FIDO key did not return both hmac-secret outputs"))
    }

    /// Run one assertion with the given hmac-secret request. The caller must
    /// `wipe` the returned assertions once it has extracted the secret.
    fn hmac_secret(
        &self,
        credential_id: &[u8],
        ext: AssertionExtension,
        pin: Option<&str>,
    ) -> Result<Vec<Assertion>> {
        let challenge = random_bytes::<32>();
        let extensions = [ext];
        let builder = GetAssertionArgsBuilder::new(RP_ID, &challenge)
            .credential_id(credential_id)
            .extensions(&extensions);
        let builder = match pin {
            Some(pin) => builder.pin(pin),
            None => builder.without_pin_and_uv(),
        };

        self.device
            .get_assertion_with_args(&builder.build())
            .context("FIDO key assertion failed (wrong key or wrong PIN?)")
    }
}

fn extensions(assertions: &[Assertion]) -> impl Iterator<Item = &AssertionExtension> {
    assertions.iter().flat_map(|a| &a.extensions)
}

/// Ask for the PIN on the terminal, if `needed`.
pub fn prompt_pin(needed: bool) -> Result<Option<Zeroizing<String>>> {
    if !needed {
        return Ok(None);
    }
    if let Ok(pin) = std::env::var("CARGO_CREDENTIAL_FIDO_PIN") {
        return Ok(Some(Zeroizing::new(pin)));
    }
    let pin = rpassword::prompt_password("FIDO key PIN: ").context("failed to read PIN")?;
    Ok(Some(Zeroizing::new(pin)))
}

pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut buf = [0u8; N];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    buf
}
