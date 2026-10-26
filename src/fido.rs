//! Talking to the FIDO2 authenticator.
//!
//! The authenticator never sees the cargo token. We create one non-resident
//! credential with the `hmac-secret` extension, then for each stored token ask
//! the key for HMAC(credRandom, salt). That 32-byte output is the encryption
//! key: it can only be reproduced by this physical key, with a touch.

use anyhow::{Context, Result, anyhow, bail};
use ctap_hid_fido2::fidokey::get_info::InfoOption;
use ctap_hid_fido2::fidokey::{
    AssertionExtension, GetAssertionArgsBuilder, MakeCredentialArgsBuilder,
    make_credential::Extension as MakeExtension,
};
use ctap_hid_fido2::{FidoKeyHid, FidoKeyHidFactory, LibCfg};
use rand::RngCore;
use zeroize::Zeroizing;

/// Relying-party id the credential is scoped to. It never leaves the machine.
pub const RP_ID: &str = "cargo-credential-fido";

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
    ) -> Result<Zeroizing<[u8; 32]>> {
        let challenge = random_bytes::<32>();
        let builder = GetAssertionArgsBuilder::new(RP_ID, &challenge)
            .credential_id(credential_id)
            .extensions(&[AssertionExtension::HmacSecret(Some(*salt))]);
        let builder = match pin {
            Some(pin) => builder.pin(pin),
            None => builder.without_pin_and_uv(),
        };

        let assertions = self
            .device
            .get_assertion_with_args(&builder.build())
            .context("FIDO key assertion failed (wrong key or wrong PIN?)")?;

        assertions
            .into_iter()
            .flat_map(|a| a.extensions)
            .find_map(|e| match e {
                AssertionExtension::HmacSecret(Some(secret)) => Some(Zeroizing::new(secret)),
                _ => None,
            })
            .ok_or_else(|| anyhow!("FIDO key did not return an hmac-secret"))
    }
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
