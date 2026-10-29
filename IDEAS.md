# Ideas

## Use the HID backend on Windows when elevated

**Problem.** On Windows every key operation goes through `webauthn.dll`
(`src/fido/windows.rs`), which shows its own Windows Security dialog and
asks for the PIN on every call. It never hands the PIN or the
`pinUvAuthToken` to the caller, so nothing can be cached. `migrate` with
N tokens, or `rotate --all`, means N PIN prompts, where the HID backend
(`src/fido/hid.rs`) asks once per process (`OnceCell`).

**Why not today.** Since Windows 10 1903 only elevated processes can open a
FIDO key as a HID device, and cargo cannot start an elevated provider, so
the Windows build has no HID backend at all.

**Idea.** `migrate` and `rotate` are run by the user, not cargo, so they can
be run from an elevated terminal (and so can `cargo publish`, whose child
processes inherit the elevation). When the process is elevated, use
`HidAuthenticator`; otherwise fall back to `WebAuthnAuthenticator`.

The stores are compatible: the WebAuthn backend sets
`WEBAUTHN_AUTHENTICATOR_HMAC_SECRET_VALUES_FLAG` so salts are sent raw,
as over HID, and either backend can unseal the other's tokens.

**Work.**

1. Check that `ctap-hid-fido2` (hidapi) builds and opens keys on Windows
   when elevated.
2. In `Cargo.toml`, move `ctap-hid-fido2` from
   `[target."cfg(not(windows))".dependencies]` to `[dependencies]`, and
   drop the `#[cfg(not(windows))]` on `mod hid` in `src/fido/mod.rs`.
3. Detect elevation: `OpenProcessToken` + `GetTokenInformation(TokenElevation)`
   (`src/secure.rs` already opens the process token for the user SID).
4. In `fido::open()`, pick HID when elevated, WebAuthn otherwise.
5. With HID, `CARGO_CREDENTIAL_FIDO_PIN` works on Windows too; update the
   module docs in `src/fido/windows.rs` and the README, which say it has
   no effect there.
6. Test both backends against the same store on Windows.

**Open questions.**

- Should elevation be the trigger, or an explicit opt-in (flag or
  environment variable), since running as administrator is a trade-off of
  its own?
- Windows always verifies a key's PIN through WebAuthn, even for a
  credential registered without one. Over HID the credential's `uv` flag
  is honoured instead, so a no-PIN credential on a key that later got a
  PIN would become usable on Windows when elevated. Check that the error
  in `hmac_secret` and the README still describe this correctly.
