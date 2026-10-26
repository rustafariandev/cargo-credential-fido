//! CTAP2 over HID, for Linux and macOS.

use super::{Authenticator, Credential, Key, RP_ID, new_key, random_bytes};
use anyhow::{Context, Result, anyhow, bail};
use ctap_hid_fido2::fidokey::get_assertion::get_assertion_params::Assertion;
use ctap_hid_fido2::fidokey::get_info::InfoOption;
use ctap_hid_fido2::fidokey::{
    AssertionExtension, GetAssertionArgsBuilder, MakeCredentialArgsBuilder,
    make_credential::Extension as MakeExtension,
};
use ctap_hid_fido2::{FidoKeyHid, FidoKeyHidFactory, LibCfg};
use std::cell::OnceCell;
use zeroize::{Zeroize, Zeroizing};

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

pub struct HidAuthenticator {
    device: FidoKeyHid,
    /// The PIN, asked for at most once per process.
    pin: OnceCell<Zeroizing<String>>,
}

impl HidAuthenticator {
    pub fn open() -> Result<Self> {
        // stdout carries the cargo credential protocol, so keep-alive
        // ("touch your key") messages must go to stderr.
        let mut cfg = LibCfg::init().with_keep_alive_msg_to_stderr(true);
        cfg.keep_alive_msg = "Touch your FIDO key to continue...".to_string();
        let device = FidoKeyHidFactory::create(&cfg)
            .context("could not open FIDO key (is exactly one key plugged in?)")?;
        Ok(Self {
            device,
            pin: OnceCell::new(),
        })
    }

    /// Whether the key has a PIN configured.
    fn has_pin(&self) -> Result<bool> {
        Ok(self.device.enable_info_option(&InfoOption::ClientPin)? == Some(true))
    }

    /// The PIN if `uv` is set, asking for it the first time.
    fn pin(&self, uv: bool) -> Result<Option<&str>> {
        if !uv {
            return Ok(None);
        }
        if self.pin.get().is_none() {
            let _ = self.pin.set(prompt_pin()?);
        }
        Ok(self.pin.get().map(|p| p.as_str()))
    }

    /// Run one assertion with the given hmac-secret request. The caller must
    /// `wipe` the returned assertions once it has extracted the secret.
    fn hmac_secret(&self, cred: &Credential, ext: AssertionExtension) -> Result<Vec<Assertion>> {
        let pin = self.pin(cred.uv)?;
        let challenge = random_bytes::<32>();
        let extensions = [ext];
        let builder = GetAssertionArgsBuilder::new(RP_ID, &challenge)
            .credential_id(&cred.id)
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

impl Authenticator for HidAuthenticator {
    fn enroll(&self) -> Result<Credential> {
        let support = self.device.get_info()?.extensions;
        if !support.iter().any(|e| e == "hmac-secret") {
            bail!("this FIDO key does not support the hmac-secret extension");
        }
        // Use the PIN if the key has one, so the token also requires
        // something you know.
        let uv = self.has_pin()?;
        let pin = self.pin(uv)?;

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
        Ok(Credential {
            id: att.credential_descriptor.id,
            uv,
        })
    }

    fn derive_key(&self, cred: &Credential, salt: &[u8; 32]) -> Result<Key> {
        let ext = AssertionExtension::HmacSecret(Some(*salt));
        let mut assertions = self.hmac_secret(cred, ext)?;
        let key = extensions(&assertions).find_map(|e| match e {
            AssertionExtension::HmacSecret(Some(secret)) => Some(new_key(secret)),
            _ => None,
        });
        wipe(&mut assertions);
        key.ok_or_else(|| anyhow!("FIDO key did not return an hmac-secret"))
    }

    fn derive_key_pair(
        &self,
        cred: &Credential,
        salt1: &[u8; 32],
        salt2: &[u8; 32],
    ) -> Result<(Key, Key)> {
        let salts = (*salt1, *salt2);
        let mut assertions =
            self.hmac_secret(cred, AssertionExtension::HmacSecret2(Some(salts)))?;
        let keys = extensions(&assertions).find_map(|e| match e {
            AssertionExtension::HmacSecret2(Some((a, b))) => Some((new_key(a), new_key(b))),
            _ => None,
        });
        wipe(&mut assertions);
        keys.ok_or_else(|| anyhow!("FIDO key did not return both hmac-secret outputs"))
    }
}

fn extensions(assertions: &[Assertion]) -> impl Iterator<Item = &AssertionExtension> {
    assertions.iter().flat_map(|a| &a.extensions)
}

/// Ask for the PIN on the terminal, unless it is in the environment.
fn prompt_pin() -> Result<Zeroizing<String>> {
    if let Ok(pin) = std::env::var("CARGO_CREDENTIAL_FIDO_PIN") {
        return Ok(Zeroizing::new(pin));
    }
    let pin = rpassword::prompt_password("FIDO key PIN: ").context("failed to read PIN")?;
    Ok(Zeroizing::new(pin))
}
