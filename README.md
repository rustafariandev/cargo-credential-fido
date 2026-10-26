# cargo-credential-fido

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
   `~/Library/Application Support/cargo-credential-fido/` on macOS, mode
   0600) holds only the credential id, salts, nonces and ciphertext. It is
   useless without the physical key.
4. Decrypting needs a touch on the key, plus the key's PIN if one is set.
   Cargo caches the token for the rest of that one cargo invocation only.

Requirements: a FIDO2 key that supports `hmac-secret` (YubiKey 5, SoloKey,
Nitrokey 3, Feitian, ...). Exactly one key must be plugged in. Supported on
Linux and macOS. On macOS the process refuses debugger attachment, so it
cannot be run under `lldb`.

## Install

```sh
cargo install --path .
```

Then register it with cargo:

```sh
cargo-credential-fido configure
```

This adds the provider to `registry.global-credential-providers` in
`$CARGO_HOME/config.toml` (default `~/.cargo/config.toml`). Comments and
formatting in the file are kept. If other providers are already listed, they
stay as fallbacks; remove `cargo:token` if you never want plaintext tokens.
Doing it by hand is the same as adding:

```toml
[registry]
global-credential-providers = ["cargo-credential-fido"]
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
For other registries, use the index URL cargo reports, e.g. `sparse+https://...`.

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
| `CARGO_CREDENTIAL_FIDO_PIN` | Supply the PIN non-interactively (weakens the PIN factor) |

## Caveats

- If you lose the FIDO key, the stored tokens are gone. Revoke them on
  crates.io and issue new ones. You can also back up the token somewhere else.
- A token sealed with a PIN can only be opened with the PIN. This is because
  the key returns a different `hmac-secret` with and without user verification.
  Whether to use a PIN is decided once, at enrollment, from whether the key has
  a PIN set. To change it, delete the store file and run `login` again.

## Tests

`scripts/e2e.sh` runs the provider end to end against
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

CI (`.github/workflows/ci.yml`) runs rustfmt, clippy, `cargo test` on Linux and
macOS, and this script on every push and pull request.
