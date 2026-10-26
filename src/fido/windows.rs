//! The Windows WebAuthn API (`webauthn.dll`).
//!
//! Since Windows 10 1903, only elevated processes can open FIDO keys as HID
//! devices, and cargo cannot start an elevated provider. The WebAuthn API is
//! open to every process. Windows shows its own dialog for the PIN and the
//! touch, so the PIN never passes through this process (and
//! `CARGO_CREDENTIAL_FIDO_PIN` has no effect).
//!
//! By default Windows treats hmac-secret salts as WebAuthn PRF inputs and
//! hashes them. We set `WEBAUTHN_AUTHENTICATOR_HMAC_SECRET_VALUES_FLAG` to
//! send them raw, as the HID backend does, so a store works on every OS.

use super::{Authenticator, Credential, Key, RP_ID, new_key, random_bytes};
use anyhow::{Result, anyhow, bail};
use std::ffi::c_void;
use std::ptr::{null, null_mut};
use windows_sys::Win32::Networking::WindowsWebServices::*;
use windows_sys::Win32::UI::WindowsAndMessaging::GetForegroundWindow;
use windows_sys::core::{BOOL, HRESULT, PCWSTR};
use zeroize::Zeroize;

/// The first API version that returns hmac-secret outputs from an
/// assertion (`pHmacSecretSaltValues` and `WEBAUTHN_ASSERTION.pHmacSecret`).
const MIN_API_VERSION: u32 = WEBAUTHN_API_VERSION_4;

const TIMEOUT_MS: u32 = 60_000;

/// The user-verified bit in the authenticator data flags.
const FLAG_UV: u8 = 0x04;

pub struct WebAuthnAuthenticator;

impl WebAuthnAuthenticator {
    pub fn open() -> Result<Self> {
        let version = unsafe { WebAuthNGetApiVersionNumber() };
        if version < MIN_API_VERSION {
            bail!(
                "this version of Windows is too old: its WebAuthn API (version {version}) \
                 cannot return hmac-secret outputs; version {MIN_API_VERSION} is needed"
            );
        }
        Ok(Self)
    }

    /// Run one assertion and return the hmac-secret outputs for `salt1` and,
    /// if given, `salt2`.
    fn hmac_secret(
        &self,
        cred: &Credential,
        salt1: &[u8; 32],
        salt2: Option<&[u8; 32]>,
    ) -> Result<(Key, Option<Key>)> {
        let rp_id = wide(RP_ID);
        let client_json = client_data("webauthn.get");
        let client = client_data_ref(&client_json);

        let mut id = cred.id.clone();
        let mut allowed = WEBAUTHN_CREDENTIAL {
            dwVersion: WEBAUTHN_CREDENTIAL_CURRENT_VERSION,
            cbId: len32(&id),
            pbId: id.as_mut_ptr(),
            pwszCredentialType: WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY,
        };
        let mut first = *salt1;
        let mut second = salt2.copied();
        let mut salt = WEBAUTHN_HMAC_SECRET_SALT {
            cbFirst: 32,
            pbFirst: first.as_mut_ptr(),
            cbSecond: if second.is_some() { 32 } else { 0 },
            pbSecond: second.as_mut().map_or(null_mut(), |s| s.as_mut_ptr()),
        };
        let mut salts = WEBAUTHN_HMAC_SECRET_SALT_VALUES {
            pGlobalHmacSalt: &mut salt,
            cCredWithHmacSecretSaltList: 0,
            pCredWithHmacSecretSaltList: null_mut(),
        };

        let mut opts: WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS = unsafe { std::mem::zeroed() };
        opts.dwVersion = WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS_VERSION_6;
        opts.dwTimeoutMilliseconds = TIMEOUT_MS;
        opts.CredentialList = WEBAUTHN_CREDENTIALS {
            cCredentials: 1,
            pCredentials: &mut allowed,
        };
        opts.dwAuthenticatorAttachment = WEBAUTHN_AUTHENTICATOR_ATTACHMENT_CROSS_PLATFORM;
        opts.dwUserVerificationRequirement = if cred.uv {
            WEBAUTHN_USER_VERIFICATION_REQUIREMENT_REQUIRED
        } else {
            WEBAUTHN_USER_VERIFICATION_REQUIREMENT_DISCOURAGED
        };
        opts.pHmacSecretSaltValues = &mut salts;
        // Send the salts as they are, not hashed as PRF inputs.
        opts.dwFlags = WEBAUTHN_AUTHENTICATOR_HMAC_SECRET_VALUES_FLAG;

        eprintln!("Follow the Windows Security prompt to use your FIDO key.");
        let mut raw = null_mut();
        check(unsafe {
            WebAuthNAuthenticatorGetAssertion(
                GetForegroundWindow(),
                rp_id.as_ptr(),
                &client,
                &opts,
                &mut raw,
            )
        })?;
        let assertion = AssertionGuard(raw);
        let a = unsafe { &*assertion.0 };

        // The secret differs with and without user verification, so a
        // mismatch would only show up later as a decryption failure.
        let data = unsafe { slice(a.pbAuthenticatorData, a.cbAuthenticatorData) };
        if user_verified(data)? != cred.uv {
            bail!(if cred.uv {
                "the FIDO key did not verify the PIN, which this credential needs"
            } else {
                "Windows verified a PIN, but this credential was registered without one"
            });
        }

        if a.dwVersion < WEBAUTHN_ASSERTION_VERSION_3 || a.pHmacSecret.is_null() {
            bail!("FIDO key did not return an hmac-secret");
        }
        let out = unsafe { &*a.pHmacSecret };
        let key1 = unsafe { secret(out.pbFirst, out.cbFirst) }
            .ok_or_else(|| anyhow!("FIDO key did not return an hmac-secret"))?;
        let key2 = match salt2 {
            None => None,
            Some(_) => Some(
                unsafe { secret(out.pbSecond, out.cbSecond) }
                    .ok_or_else(|| anyhow!("FIDO key did not return both hmac-secret outputs"))?,
            ),
        };
        Ok((key1, key2))
    }
}

impl Authenticator for WebAuthnAuthenticator {
    fn enroll(&self) -> Result<Credential> {
        let rp_id = wide(RP_ID);
        let rp = WEBAUTHN_RP_ENTITY_INFORMATION {
            dwVersion: WEBAUTHN_RP_ENTITY_INFORMATION_CURRENT_VERSION,
            pwszId: rp_id.as_ptr(),
            pwszName: rp_id.as_ptr(),
            pwszIcon: null(),
        };
        // The credential is not resident, so the user handle is never read
        // back; it only has to be present.
        let mut user_id = random_bytes::<16>();
        let user_name = wide("cargo");
        let user = WEBAUTHN_USER_ENTITY_INFORMATION {
            dwVersion: WEBAUTHN_USER_ENTITY_INFORMATION_CURRENT_VERSION,
            cbId: len32(&user_id),
            pbId: user_id.as_mut_ptr(),
            pwszName: user_name.as_ptr(),
            pwszIcon: null(),
            pwszDisplayName: user_name.as_ptr(),
        };
        let mut es256 = WEBAUTHN_COSE_CREDENTIAL_PARAMETER {
            dwVersion: WEBAUTHN_COSE_CREDENTIAL_PARAMETER_CURRENT_VERSION,
            pwszCredentialType: WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY,
            lAlg: WEBAUTHN_COSE_ALGORITHM_ECDSA_P256_WITH_SHA256,
        };
        let params = WEBAUTHN_COSE_CREDENTIAL_PARAMETERS {
            cCredentialParameters: 1,
            pCredentialParameters: &mut es256,
        };
        let client_json = client_data("webauthn.create");
        let client = client_data_ref(&client_json);

        let mut hmac_secret: BOOL = 1;
        let mut ext = WEBAUTHN_EXTENSION {
            pwszExtensionIdentifier: WEBAUTHN_EXTENSIONS_IDENTIFIER_HMAC_SECRET,
            cbExtension: size_of::<BOOL>() as u32,
            pvExtension: (&raw mut hmac_secret).cast::<c_void>(),
        };
        let mut opts: WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS =
            unsafe { std::mem::zeroed() };
        opts.dwVersion = WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS_VERSION_1;
        opts.dwTimeoutMilliseconds = TIMEOUT_MS;
        opts.Extensions = WEBAUTHN_EXTENSIONS {
            cExtensions: 1,
            pExtensions: &mut ext,
        };
        opts.dwAuthenticatorAttachment = WEBAUTHN_AUTHENTICATOR_ATTACHMENT_CROSS_PLATFORM;
        // Windows cannot tell us whether the key has a PIN. "Preferred" uses
        // it if there is one, and the UV flag in the result says which.
        opts.dwUserVerificationRequirement = WEBAUTHN_USER_VERIFICATION_REQUIREMENT_PREFERRED;
        opts.dwAttestationConveyancePreference = WEBAUTHN_ATTESTATION_CONVEYANCE_PREFERENCE_NONE;

        eprintln!("Registering a new credential: follow the Windows Security prompt.");
        let mut raw = null_mut();
        check(unsafe {
            WebAuthNAuthenticatorMakeCredential(
                GetForegroundWindow(),
                &rp,
                &user,
                &params,
                &client,
                &opts,
                &mut raw,
            )
        })?;
        let att = AttestationGuard(raw);
        let a = unsafe { &*att.0 };

        let ext = unsafe { slice(a.Extensions.pExtensions, a.Extensions.cExtensions) };
        let hmac_enabled = ext.iter().any(|e| unsafe {
            wide_eq(
                e.pwszExtensionIdentifier,
                WEBAUTHN_EXTENSIONS_IDENTIFIER_HMAC_SECRET,
            ) && e.cbExtension as usize == size_of::<BOOL>()
                && *e.pvExtension.cast::<BOOL>() != 0
        });
        if !hmac_enabled {
            bail!("FIDO key did not enable hmac-secret for the new credential");
        }
        let data = unsafe { slice(a.pbAuthenticatorData, a.cbAuthenticatorData) };
        Ok(Credential {
            id: unsafe { slice(a.pbCredentialId, a.cbCredentialId) }.to_vec(),
            uv: user_verified(data)?,
        })
    }

    fn derive_key(&self, cred: &Credential, salt: &[u8; 32]) -> Result<Key> {
        Ok(self.hmac_secret(cred, salt, None)?.0)
    }

    fn derive_key_pair(
        &self,
        cred: &Credential,
        salt1: &[u8; 32],
        salt2: &[u8; 32],
    ) -> Result<(Key, Key)> {
        match self.hmac_secret(cred, salt1, Some(salt2))? {
            (a, Some(b)) => Ok((a, b)),
            (_, None) => unreachable!("a second salt always gives a second output"),
        }
    }
}

/// Frees an assertion, wiping its hmac-secret outputs first: Windows
/// allocated them, so our zeroizing allocator never sees them.
struct AssertionGuard(*mut WEBAUTHN_ASSERTION);

impl Drop for AssertionGuard {
    fn drop(&mut self) {
        unsafe {
            let a = &*self.0;
            if a.dwVersion >= WEBAUTHN_ASSERTION_VERSION_3 && !a.pHmacSecret.is_null() {
                let out = &*a.pHmacSecret;
                slice_mut(out.pbFirst, out.cbFirst).zeroize();
                slice_mut(out.pbSecond, out.cbSecond).zeroize();
            }
            WebAuthNFreeAssertion(self.0);
        }
    }
}

struct AttestationGuard(*mut WEBAUTHN_CREDENTIAL_ATTESTATION);

impl Drop for AttestationGuard {
    fn drop(&mut self) {
        unsafe { WebAuthNFreeCredentialAttestation(self.0) }
    }
}

/// Client data for a WebAuthn call. Windows only hashes it into the request;
/// nothing checks it, since we never verify the signatures.
fn client_data(kind: &str) -> Vec<u8> {
    let challenge = hex::encode(random_bytes::<32>());
    format!(r#"{{"type":"{kind}","challenge":"{challenge}","origin":"{RP_ID}"}}"#).into_bytes()
}

fn client_data_ref(json: &[u8]) -> WEBAUTHN_CLIENT_DATA {
    WEBAUTHN_CLIENT_DATA {
        dwVersion: WEBAUTHN_CLIENT_DATA_CURRENT_VERSION,
        cbClientDataJSON: len32(json),
        // Windows does not write to it.
        pbClientDataJSON: json.as_ptr().cast_mut(),
        pwszHashAlgId: WEBAUTHN_HASH_ALGORITHM_SHA_256,
    }
}

/// Whether the authenticator data says the user was verified (PIN).
fn user_verified(auth_data: &[u8]) -> Result<bool> {
    // rpIdHash (32 bytes), then the flags byte.
    let flags = auth_data
        .get(32)
        .ok_or_else(|| anyhow!("FIDO key returned truncated authenticator data"))?;
    Ok(flags & FLAG_UV != 0)
}

/// Copy a 32-byte hmac-secret output into a key.
unsafe fn secret(ptr: *const u8, len: u32) -> Option<Key> {
    let bytes = unsafe { slice(ptr, len) };
    <&[u8; 32]>::try_from(bytes).ok().map(new_key)
}

fn check(hr: HRESULT) -> Result<()> {
    if hr >= 0 {
        return Ok(());
    }
    let name = unsafe { from_wide(WebAuthNGetErrorName(hr)) };
    Err(anyhow!(
        "WebAuthn request failed: {name} (HRESULT {hr:#010x})"
    ))
}

unsafe fn slice<'a, T>(ptr: *const T, len: u32) -> &'a [T] {
    if ptr.is_null() || len == 0 {
        return &[];
    }
    unsafe { std::slice::from_raw_parts(ptr, len as usize) }
}

unsafe fn slice_mut<'a, T>(ptr: *mut T, len: u32) -> &'a mut [T] {
    if ptr.is_null() || len == 0 {
        return &mut [];
    }
    unsafe { std::slice::from_raw_parts_mut(ptr, len as usize) }
}

fn len32(bytes: &[u8]) -> u32 {
    u32::try_from(bytes.len()).expect("WebAuthn buffers are small")
}

/// A NUL-terminated UTF-16 copy of `s`.
fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain([0]).collect()
}

unsafe fn wide_slice<'a>(p: PCWSTR) -> &'a [u16] {
    if p.is_null() {
        return &[];
    }
    let mut len = 0;
    while unsafe { *p.add(len) } != 0 {
        len += 1;
    }
    unsafe { std::slice::from_raw_parts(p, len) }
}

unsafe fn wide_eq(a: PCWSTR, b: PCWSTR) -> bool {
    unsafe { wide_slice(a) == wide_slice(b) }
}

unsafe fn from_wide(p: PCWSTR) -> String {
    String::from_utf16_lossy(unsafe { wide_slice(p) })
}
