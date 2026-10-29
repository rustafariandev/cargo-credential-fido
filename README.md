# cargo-credential-fido

[![crates.io](https://img.shields.io/crates/v/cargo-credential-fido.svg)](https://crates.io/crates/cargo-credential-fido)

A [cargo credential provider](https://doc.rust-lang.org/cargo/reference/registry-authentication.html)
that keeps your registry API token encrypted at rest. Only your FIDO2 security key can decrypt it.

## How it works

1. On first `login`, a non-resident FIDO2 credential with the `hmac-secret`
   extension is created on your key, under the RP id `cargo-credential-fido`.
2. Each token gets a random 32-byte salt. The key computes
   `HMAC(credential secret, salt)`, and that output becomes the
   XChaCha20-Poly1305 key that encrypts the token. The registry URL is
   bound in as associated data.
3. The store (`store.json` in `~/.config/cargo-credential-fido/` on Linux,
   `~/Library/Application Support/cargo-credential-fido/` on macOS,
   `%APPDATA%\cargo-credential-fido\` on Windows) holds only the credential
   id, salts, nonces and ciphertext. It is readable only by you (mode 0600 on
   Linux and macOS; on Windows, a DACL for you and SYSTEM in place of the
   folder's permissions). It is useless without the physical key.
4. Decrypting needs a touch on the key, plus the key's PIN if one is set.
   Cargo caches the token for the rest of that one cargo invocation only.

Requirements: a FIDO2 key that supports `hmac-secret` (YubiKey 5, SoloKey,
Nitrokey 3, Feitian, ...). On Linux and macOS, exactly one key must be
plugged in. Supported on Linux, macOS and Windows. On macOS the process
refuses debugger attachment, so it cannot be run under `lldb`.

On Windows, only elevated processes can talk to a FIDO key directly, so the
provider goes through the Windows WebAuthn API instead (API version 4 or
later; it says so if Windows is too old). Windows shows its own dialog for
the PIN and the touch, and `CARGO_CREDENTIAL_FIDO_PIN` has no effect there.
No admin rights are needed.

On Windows the process also stops other processes of the same user from
opening it to read its memory (they can still borrow the handle cargo holds on
it, so this raises the bar rather than closing the door), refuses DLLs from
remote or low-integrity locations, keeps its heap out of Windows Error
Reporting dumps, and loads `webauthn.dll` from System32 only. Windows has no
`mlockall`: to keep secrets out of the page file and hibernation file, use
BitLocker or `fsutil behavior set EncryptPagingFile 1`.

## Install

The crate is published on [crates.io](https://crates.io/crates/cargo-credential-fido).

```sh
cargo install cargo-credential-fido
```

On Linux, building needs the libudev headers and `pkg-config` (for hidapi):

```sh
sudo apt install libudev-dev pkg-config     # Debian/Ubuntu
sudo dnf install systemd-devel pkgconf      # Fedora
```

On macOS, hidapi uses the system IOKit framework, so only the Xcode Command
Line Tools are needed (Rust needs them for linking anyway):

```sh
xcode-select --install
```

On Windows, nothing beyond a Rust toolchain is needed.

To install from a checkout of this repository instead, run
`cargo install --path .`.

Then register it with cargo:

```sh
cargo-credential-fido configure
```

This adds the provider to `registry.global-credential-providers` in
`$CARGO_HOME/config.toml` (default `~/.cargo/config.toml`). Comments and
formatting in the file are kept. If other providers are already listed, they
stay as fallbacks. If none are, `cargo:token` (cargo's default) is kept as a
fallback, so tokens still in `credentials.toml` keep working; remove it once
they are migrated if you never want plaintext tokens. Doing it by hand is the
same as adding:

```toml
[registry]
global-credential-providers = ["cargo:token", "cargo-credential-fido"]
```

## Use

```sh
cargo login              # paste your crates.io token, touch the key
cargo publish            # touch the key when asked
cargo logout             # forget the stored token
```

Or standalone:

```sh
cargo-credential-fido login  [INDEX_URL]   # token read from a prompt or stdin
cargo-credential-fido get    [INDEX_URL]   # print the decrypted token
cargo-credential-fido logout [INDEX_URL]
cargo-credential-fido list
cargo-credential-fido rotate [INDEX_URL|--all]  # re-encrypt under a new salt
cargo-credential-fido configure                 # register with cargo
cargo-credential-fido migrate [--keep]          # import tokens from credentials.toml
```

`INDEX_URL` defaults to crates.io (`https://github.com/rust-lang/crates.io-index`).
Any crates.io index URL, such as `sparse+https://index.crates.io/`, means the
same. For other registries, use the index URL cargo reports, e.g.
`sparse+https://...`; a missing trailing `/` is added to sparse URLs.

## Rotating the salt

`rotate` decrypts a token and encrypts it again under a fresh random salt and
nonce, so a copy of the old store file can no longer be matched to the
current one. It uses the two-salt form of `hmac-secret`: one assertion
returns both the old and the new key, so each token needs a single touch.
The token itself and the credential on the key stay the same, so
this does not replace revoking a leaked token. The store is written only
after every token is rotated, so a failure leaves it unchanged.

## Migrating from a plaintext token

If `$CARGO_HOME/credentials.toml` already contains tokens, run:

```sh
cargo-credential-fido migrate
```

This encrypts every token in the file: the crates.io one under `[registry]`
and the ones under `[registries.NAME]`. It needs one touch per token. Then it
removes them from `credentials.toml`, keeping the rest of the file. The store
is saved before `credentials.toml` is changed, so a failure never loses a
token. Pass `--keep` to leave the plaintext tokens in place.

To find the index URL of an alternative registry, `migrate` looks at
`registries.NAME.index` in `$CARGO_HOME/config.toml`, or at
`CARGO_REGISTRIES_NAME_INDEX`. A registry it cannot resolve is skipped and its
token is left in the file; store that one with `login INDEX_URL` instead.

## Environment

| Variable | Purpose |
|---|---|
| `CARGO_CREDENTIAL_FIDO_STORE` | Use a different store file |
| `CARGO_CREDENTIAL_FIDO_PIN` | Supply the PIN non-interactively (weakens the PIN factor). Linux and macOS only |

## Caveats

- If you lose the FIDO key, the stored tokens are gone. Revoke them on
  crates.io and issue new ones. You can also back up the token somewhere else.
- A token sealed with a PIN can only be opened with the PIN. This is because
  the key returns a different `hmac-secret` with and without user verification.
  Whether to use a PIN is decided once, at enrollment, from whether the key has
  a PIN set. To change it, delete the store file and run `login` again.
  Changing the PIN itself is fine: the secret depends on whether the PIN is
  used, not on its value.
- Setting a PIN on a key whose tokens were sealed without one locks those
  tokens out on Windows: Windows always verifies the PIN of a key that has
  one, so it can only reach the PIN-verified secret. Linux and macOS can still
  open them. Back them up with `get` first, or read them on Linux or macOS,
  then delete the store file and run `login` again.
- Do not turn on `alwaysUv` on a key (an option on some keys, such as YubiKey
  5.7+) while it holds tokens sealed without a PIN. The key then always uses
  the PIN-verified secret, so those tokens can no longer be decrypted. Back
  them up with `get` first, then delete the store file and run `login` again
  for each one after turning it on.

## Tests

`cargo test` runs on every OS, using a software authenticator in place of a
real key.

On Linux, `scripts/e2e.sh` runs the provider end to end against
[virtual-fido](https://github.com/rustafariandev/virtual-fido-rs), a software
FIDO2 key that appears as a real HID device through `/dev/uhid`. It covers
login, get, list, rotate, logout, configure, migrate, `cargo login`/`logout`
through the provider, and a key with a PIN. It needs sudo and python-fido2
0.9.x, and refuses to run while another FIDO key is plugged in:

```sh
cargo build --manifest-path ../virtual-fido-rs/Cargo.toml --no-default-features
pip install "fido2==0.9.3"
scripts/e2e.sh ../virtual-fido-rs/target/debug/virtual-fido
```

CI (`.github/workflows/ci.yml`) runs rustfmt, clippy and `cargo test` on Linux,
macOS and Windows, and this script on Linux, on every push and pull request.
The Windows WebAuthn backend has no automated end-to-end test, since it needs
a real key and the Windows Security dialog.
