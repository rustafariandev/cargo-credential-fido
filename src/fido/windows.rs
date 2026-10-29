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
//!
//! `webauthn.dll` is loaded at run time, from System32 only, rather than
//! imported. An import is resolved before `main` runs: Windows without the
//! DLL would refuse to start the process instead of letting us report that
//! it is too old, and the default search order would load a `webauthn.dll`
//! planted next to the executable.

use super::{Authenticator, Credential, Key, RP_ID, new_key, random_bytes};
use crate::win::{from_wide, wide, wide_eq};
use anyhow::{Result, anyhow, bail};
use std::ffi::{CStr, c_void};
use std::ptr::{null, null_mut};
use windows_sys::Win32::Foundation::{HMODULE, HWND};
use windows_sys::Win32::Networking::WindowsWebServices::*;
use windows_sys::Win32::System::Console::GetConsoleWindow;
use windows_sys::Win32::System::LibraryLoader::{
    GetProcAddress, LOAD_LIBRARY_SEARCH_SYSTEM32, LoadLibraryExW,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    GA_ROOTOWNER, GetAncestor, GetForegroundWindow, IsWindowVisible,
};
use windows_sys::core::{BOOL, HRESULT, PCWSTR};
use zeroize::Zeroize;

/// The first API version that returns hmac-secret outputs from an
/// assertion (`pHmacSecretSaltValues` and `WEBAUTHN_ASSERTION.pHmacSecret`).
const MIN_API_VERSION: u32 = WEBAUTHN_API_VERSION_4;

const TIMEOUT_MS: u32 = 60_000;

/// The user-verified bit in the authenticator data flags.
const FLAG_UV: u8 = 0x04;

/// The `webauthn.dll` functions we call.
struct Api {
    get_api_version_number: unsafe extern "system" fn() -> u32,
    get_assertion: unsafe extern "system" fn(
        HWND,
        PCWSTR,
        *const WEBAUTHN_CLIENT_DATA,
        *const WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS,
        *mut *mut WEBAUTHN_ASSERTION,
    ) -> HRESULT,
    make_credential: unsafe extern "system" fn(
        HWND,
        *const WEBAUTHN_RP_ENTITY_INFORMATION,
        *const WEBAUTHN_USER_ENTITY_INFORMATION,
        *const WEBAUTHN_COSE_CREDENTIAL_PARAMETERS,
        *const WEBAUTHN_CLIENT_DATA,
        *const WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS,
        *mut *mut WEBAUTHN_CREDENTIAL_ATTESTATION,
    ) -> HRESULT,
    free_assertion: unsafe extern "system" fn(*const WEBAUTHN_ASSERTION),
    free_credential_attestation: unsafe extern "system" fn(*const WEBAUTHN_CREDENTIAL_ATTESTATION),
    get_error_name: unsafe extern "system" fn(HRESULT) -> PCWSTR,
}

impl Api {
    fn load() -> Result<Self> {
        let name = wide("webauthn.dll");
        let module =
            unsafe { LoadLibraryExW(name.as_ptr(), null_mut(), LOAD_LIBRARY_SEARCH_SYSTEM32) };
        if module.is_null() {
            bail!("this version of Windows is too old: it has no WebAuthn API (webauthn.dll)");
        }
        // The module is never freed, so the pointers stay valid for the life
        // of the process. Each field's type matches the SDK prototype.
        unsafe {
            Ok(Self {
                get_api_version_number: proc(module, c"WebAuthNGetApiVersionNumber")?,
                get_assertion: proc(module, c"WebAuthNAuthenticatorGetAssertion")?,
                make_credential: proc(module, c"WebAuthNAuthenticatorMakeCredential")?,
                free_assertion: proc(module, c"WebAuthNFreeAssertion")?,
                free_credential_attestation: proc(module, c"WebAuthNFreeCredentialAttestation")?,
                get_error_name: proc(module, c"WebAuthNGetErrorName")?,
            })
        }
    }

    fn check(&self, hr: HRESULT) -> Result<()> {
        if hr >= 0 {
            return Ok(());
        }
        let name = unsafe { from_wide((self.get_error_name)(hr)) };
        Err(anyhow!(
            "WebAuthn request failed: {name} (HRESULT {hr:#010x})"
        ))
    }
}

/// Look up the function `name` in `module`.
///
/// # Safety
///
/// `F` must be a function pointer type matching the function's prototype.
unsafe fn proc<F: Copy>(module: HMODULE, name: &CStr) -> Result<F> {
    let f = unsafe { GetProcAddress(module, name.as_ptr().cast()) }
        .ok_or_else(|| anyhow!("webauthn.dll has no {}", name.to_string_lossy()))?;
    assert_eq!(size_of::<F>(), size_of_val(&f));
    Ok(unsafe { std::mem::transmute_copy(&f) })
}

pub struct WebAuthnAuthenticator {
    api: Api,
}

impl WebAuthnAuthenticator {
    pub fn open() -> Result<Self> {
        let api = Api::load()?;
        let version = unsafe { (api.get_api_version_number)() };
        if version < MIN_API_VERSION {
            bail!(
                "this version of Windows is too old: its WebAuthn API (version {version}) \
                 cannot return hmac-secret outputs; version {MIN_API_VERSION} is needed"
            );
        }
        Ok(Self { api })
    }

    /// Run one assertion and return the hmac-secret output for each of the
    /// one or two salts.
    fn hmac_secret<const N: usize>(
        &self,
        cred: &Credential,
        salts: [&[u8; 32]; N],
    ) -> Result<[Key; N]> {
        const { assert!(N == 1 || N == 2, "hmac-secret takes one or two salts") };
        let rp_id = wide(RP_ID);
        let client_json = client_data("webauthn.get");
        let client = client_data_ref(&client_json);

        let mut allowed = WEBAUTHN_CREDENTIAL {
            dwVersion: WEBAUTHN_CREDENTIAL_CURRENT_VERSION,
            cbId: len32(&cred.id),
            // Windows does not write to it.
            pbId: cred.id.as_ptr().cast_mut(),
            pwszCredentialType: WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY,
        };
        let mut first = *salts[0];
        let mut second = salts.get(1).map(|s| **s);
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
        self.api.check(unsafe {
            (self.api.get_assertion)(parent_window(), rp_id.as_ptr(), &client, &opts, &mut raw)
        })?;
        let assertion = AssertionGuard(&self.api, raw);
        let a = unsafe { &*assertion.1 };

        // The secret differs with and without user verification, so a
        // mismatch would only show up later as a decryption failure.
        let data = unsafe { slice(a.pbAuthenticatorData, a.cbAuthenticatorData) };
        if user_verified(data)? != cred.uv {
            // Windows always verifies the PIN of a key that has one, even
            // when asked not to, so the secret without the PIN is out of
            // reach here.
            bail!(if cred.uv {
                "the FIDO key did not verify the PIN, which this credential needs"
            } else {
                "this credential was registered without a PIN, but the FIDO key now has \
                 one, and Windows always uses it, so these tokens cannot be decrypted on \
                 Windows. Read them with `get` on Linux or macOS, then delete the store \
                 file and run `login` again"
            });
        }

        if a.dwVersion < WEBAUTHN_ASSERTION_VERSION_3 || a.pHmacSecret.is_null() {
            bail!("FIDO key did not return an hmac-secret");
        }
        let out = unsafe { &*a.pHmacSecret };
        let outputs = [(out.pbFirst, out.cbFirst), (out.pbSecond, out.cbSecond)];
        let keys: Vec<Key> = outputs[..N]
            .iter()
            .map_while(|&(ptr, len)| unsafe { secret(ptr, len) })
            .collect();
        keys.try_into()
            .map_err(|_| anyhow!("FIDO key did not return every hmac-secret output"))
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
        self.api.check(unsafe {
            (self.api.make_credential)(
                parent_window(),
                &rp,
                &user,
                &params,
                &client,
                &opts,
                &mut raw,
            )
        })?;
        let att = AttestationGuard(&self.api, raw);
        let a = unsafe { &*att.1 };

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
        let [key] = self.hmac_secret(cred, [salt])?;
        Ok(key)
    }

    fn derive_key_pair(
        &self,
        cred: &Credential,
        salt1: &[u8; 32],
        salt2: &[u8; 32],
    ) -> Result<(Key, Key)> {
        let [key1, key2] = self.hmac_secret(cred, [salt1, salt2])?;
        Ok((key1, key2))
    }
}

/// Frees an assertion, wiping its hmac-secret outputs first: Windows
/// allocated them, so our zeroizing allocator never sees them.
struct AssertionGuard<'a>(&'a Api, *mut WEBAUTHN_ASSERTION);

impl Drop for AssertionGuard<'_> {
    fn drop(&mut self) {
        unsafe {
            let a = &*self.1;
            if a.dwVersion >= WEBAUTHN_ASSERTION_VERSION_3 && !a.pHmacSecret.is_null() {
                let out = &*a.pHmacSecret;
                slice_mut(out.pbFirst, out.cbFirst).zeroize();
                slice_mut(out.pbSecond, out.cbSecond).zeroize();
            }
            (self.0.free_assertion)(self.1);
        }
    }
}

struct AttestationGuard<'a>(&'a Api, *mut WEBAUTHN_CREDENTIAL_ATTESTATION);

impl Drop for AttestationGuard<'_> {
    fn drop(&mut self) {
        unsafe { (self.0.free_credential_attestation)(self.1) }
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

/// The window the Windows Security dialog belongs to: the terminal cargo
/// runs in, so the dialog stays with it even if the user has switched to
/// another window. Under ConPTY (Windows Terminal, VS Code) the console
/// window is a hidden pseudo-window, owned by the terminal's window in
/// recent versions, so we take its root owner. If that is still hidden, or
/// there is no console, the foreground window, which is usually the one the
/// user started cargo from.
fn parent_window() -> HWND {
    unsafe {
        let console = GetConsoleWindow();
        if !console.is_null() {
            let owner = GetAncestor(console, GA_ROOTOWNER);
            if !owner.is_null() && IsWindowVisible(owner) != 0 {
                return owner;
            }
        }
        GetForegroundWindow()
    }
}
