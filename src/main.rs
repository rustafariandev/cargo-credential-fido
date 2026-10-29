//! A cargo credential provider that keeps registry tokens encrypted with a
//! FIDO2 security key (via the `hmac-secret` extension).
//!
//! As a cargo provider (`cargo login`, `cargo publish`, ...):
//!     [registry]
//!     global-credential-providers = ["cargo-credential-fido"]
//!
//! Standalone:
//!     cargo-credential-fido login  [INDEX_URL]   # store a token (read from stdin)
//!     cargo-credential-fido get    [INDEX_URL]   # print the decrypted token
//!     cargo-credential-fido logout [INDEX_URL]   # forget a token
//!     cargo-credential-fido list                 # list registries with a token
//!     cargo-credential-fido rotate [INDEX_URL|--all]  # re-encrypt under a new salt
//!     cargo-credential-fido configure            # add this provider to cargo's config
//!     cargo-credential-fido migrate [--keep]     # move tokens out of credentials.toml

mod config;
mod fido;
mod secure;
mod store;
#[cfg(windows)]
mod win;

use anyhow::{Context, Result, bail};
use cargo_credential::{
    Action, CacheControl, Credential, CredentialResponse, Error, RegistryInfo, Secret,
};
use fido::Authenticator;
use std::io::{IsTerminal, Read, Write};
use store::Store;
use zeroize::Zeroizing;

#[global_allocator]
static ALLOC: secure::ZeroizingAlloc = secure::ZeroizingAlloc;

/// The index URL cargo reports for crates.io, regardless of protocol.
const CRATES_IO_INDEX: &str = "https://github.com/rust-lang/crates.io-index";

struct FidoCredential;

impl Credential for FidoCredential {
    fn perform(
        &self,
        registry: &RegistryInfo<'_>,
        action: &Action<'_>,
        _args: &[&str],
    ) -> Result<CredentialResponse, Error> {
        match action {
            Action::Get(_) => {
                let token = get(registry.index_url)?.ok_or(Error::NotFound)?;
                Ok(CredentialResponse::Get {
                    token: Secret::from(token.to_string()),
                    cache: CacheControl::Session,
                    operation_independent: true,
                })
            }
            Action::Login(options) => {
                let token =
                    Zeroizing::new(cargo_credential::read_token(options, registry)?.expose());
                login(registry.index_url, &token)?;
                Ok(CredentialResponse::Login)
            }
            Action::Logout => {
                if logout(registry.index_url)? {
                    Ok(CredentialResponse::Logout)
                } else {
                    Err(Error::NotFound)
                }
            }
            _ => Err(Error::OperationNotSupported),
        }
    }
}

fn login(index_url: &str, token: &str) -> Result<()> {
    if token.trim().is_empty() {
        bail!("refusing to store an empty token");
    }
    let mut store = Store::load()?;
    let auth = fido::open()?;
    let cred = unlock(&mut store, auth.as_ref())?;

    store.seal(auth.as_ref(), &cred, index_url, token)?;
    store.save()?;
    eprintln!(
        "Token for {index_url} stored in {}",
        store::path()?.display()
    );
    Ok(())
}

/// Get the store's credential, registering a new credential on the key
/// first if the store has none.
fn unlock(store: &mut Store, auth: &dyn Authenticator) -> Result<fido::Credential> {
    if let Some(cred) = store.credential.clone() {
        return Ok(cred);
    }
    let cred = auth.enroll()?;
    store.credential = Some(cred.clone());
    eprintln!("Touch your FIDO key again to encrypt the token.");
    Ok(cred)
}

/// Added to a failure partway through `migrate` or `rotate`, which only
/// write their files once every token is done.
const NOTHING_CHANGED: &str = "stopped partway, nothing was changed (run the command again)";

/// Move the plaintext tokens in cargo's credentials file into the store.
/// Unless `keep` is set, they are then removed from the credentials file.
fn migrate(keep: bool) -> Result<()> {
    let Some(mut creds) = config::Credentials::load()? else {
        bail!("no cargo credentials file found");
    };
    // Each token with its index URL.
    let mut tokens = Vec::new();
    for t in creds.tokens(CRATES_IO_INDEX)? {
        match t.index_url.clone() {
            Some(index_url) => tokens.push((index_url, t)),
            None => eprintln!(
                "Skipping registry `{}`: no index URL for it in cargo's config.",
                t.label()
            ),
        }
    }
    if tokens.is_empty() {
        bail!("no tokens to migrate in {}", creds.path().display());
    }
    // Check before opening the key, so no touches are wasted.
    if let Some((_, t)) = tokens.iter().find(|(_, t)| t.token.trim().is_empty()) {
        bail!("the token for {} is empty", t.label());
    }

    let mut store = Store::load()?;
    let auth = fido::open()?;
    let cred = unlock(&mut store, auth.as_ref())?;
    for (i, (index_url, t)) in tokens.iter().enumerate() {
        eprintln!(
            "Encrypting the token for {} ({index_url}), {} of {}.",
            t.label(),
            i + 1,
            tokens.len()
        );
        store
            .seal(auth.as_ref(), &cred, index_url, &t.token)
            .context(NOTHING_CHANGED)?;
    }
    // Save before touching the credentials file, so a failure never leaves
    // a token in neither place.
    store.save()?;
    eprintln!(
        "Stored {} token(s) in {}",
        tokens.len(),
        store::path()?.display()
    );

    if keep {
        eprintln!("Plaintext tokens left in {}", creds.path().display());
    } else {
        for (_, t) in &tokens {
            creds.remove(t.name.as_deref());
        }
        creds.save()?;
        eprintln!(
            "Removed {} plaintext token(s) from {}",
            tokens.len(),
            creds.path().display()
        );
    }
    if !config::is_configured()? {
        eprintln!("Run `cargo-credential-fido configure` so cargo uses the stored tokens.");
    }
    Ok(())
}

fn get(index_url: &str) -> Result<Option<Zeroizing<String>>> {
    let store = Store::load()?;
    if store.credential.is_none() || !store.tokens.contains_key(index_url) {
        return Ok(None);
    }
    let auth = fido::open()?;
    store.unseal(auth.as_ref(), index_url)
}

fn logout(index_url: &str) -> Result<bool> {
    let mut store = Store::load()?;
    let removed = store.tokens.remove(index_url).is_some();
    if removed {
        store.save()?;
    }
    Ok(removed)
}

/// Re-encrypt the tokens for `index_urls` under fresh salts and nonces.
fn rotate(index_urls: &[String]) -> Result<()> {
    let mut store = Store::load()?;
    if store.credential.is_none() {
        bail!("no tokens stored");
    }
    if let Some(missing) = index_urls.iter().find(|u| !store.tokens.contains_key(*u)) {
        bail!("no token stored for {missing}");
    }
    let auth = fido::open()?;
    for (i, url) in index_urls.iter().enumerate() {
        eprintln!(
            "Rotating salt for {url}, {} of {}.",
            i + 1,
            index_urls.len()
        );
        store.rotate(auth.as_ref(), url).context(NOTHING_CHANGED)?;
    }
    // Save once at the end: if anything fails, the old entries stay intact.
    store.save()?;
    eprintln!("Rotated {} token(s).", index_urls.len());
    Ok(())
}

/// The index URL cargo reports for a registry the user typed as `url`.
/// crates.io always appears under its git index URL, whichever protocol is
/// used, and cargo requires sparse index URLs to end in `/`.
fn normalize_index_url(url: &str) -> String {
    let bare = url.trim_end_matches('/');
    let bare = bare.strip_suffix(".git").unwrap_or(bare);
    let crates_io = [
        CRATES_IO_INDEX,
        "sparse+https://index.crates.io",
        "https://index.crates.io",
    ];
    if crates_io.contains(&bare) {
        return CRATES_IO_INDEX.to_string();
    }
    if url.starts_with("sparse+") && !url.ends_with('/') {
        return format!("{url}/");
    }
    url.to_string()
}

/// The stored index URL that `url` refers to: `url` itself, or a stored URL
/// that differs from it only by a trailing `/`.
fn resolve_stored(store: &Store, url: String) -> String {
    if store.tokens.contains_key(&url) {
        return url;
    }
    let bare = url.trim_end_matches('/');
    let mut matches = store
        .tokens
        .keys()
        .filter(|k| k.trim_end_matches('/') == bare);
    match (matches.next(), matches.next()) {
        (Some(only), None) => only.clone(),
        _ => url,
    }
}

/// Longest token accepted on stdin.
const MAX_TOKEN_LEN: usize = 16 * 1024;

fn read_token_from_stdin() -> Result<Zeroizing<String>> {
    let token = if std::io::stdin().is_terminal() {
        Zeroizing::new(rpassword::prompt_password("Paste your cargo API token: ")?)
    } else {
        // Allocate up front and cap the read so the buffer never reallocates:
        // a reallocation would free the old copy without zeroing it.
        let mut buf = Zeroizing::new(String::with_capacity(MAX_TOKEN_LEN + 1));
        secure::raw_stdin()?
            .take(MAX_TOKEN_LEN as u64 + 1)
            .read_to_string(&mut buf)?;
        if buf.len() > MAX_TOKEN_LEN {
            bail!("token is longer than {MAX_TOKEN_LEN} bytes");
        }
        buf
    };
    Ok(Zeroizing::new(token.trim().to_string()))
}

fn usage() -> ! {
    eprintln!(
        "usage: cargo-credential-fido <login|get|logout> [INDEX_URL]\n       \
         cargo-credential-fido rotate [INDEX_URL|--all]\n       \
         cargo-credential-fido list\n       \
         cargo-credential-fido configure\n       \
         cargo-credential-fido migrate [--keep]\n\n\
         INDEX_URL defaults to {CRATES_IO_INDEX} (crates.io)."
    );
    std::process::exit(2);
}

fn run(args: &[String]) -> Result<()> {
    let index_url = normalize_index_url(args.get(1).map(String::as_str).unwrap_or(CRATES_IO_INDEX));
    let command = args.first().map(String::as_str);
    let index_url = if matches!(command, Some("get" | "logout" | "rotate")) {
        resolve_stored(&Store::load()?, index_url)
    } else {
        index_url
    };
    let index_url = index_url.as_str();
    match command {
        Some("login") => login(index_url, &read_token_from_stdin()?),
        Some("get") => match get(index_url)? {
            Some(token) => {
                let mut out = secure::raw_stdout()?;
                out.write_all(token.as_bytes())?;
                out.write_all(b"\n")?;
                Ok(())
            }
            None => bail!("no token stored for {index_url}"),
        },
        Some("logout") => {
            if !logout(index_url)? {
                bail!("no token stored for {index_url}");
            }
            eprintln!("Removed token for {index_url}");
            Ok(())
        }
        Some("rotate") => {
            let urls = if args.get(1).map(String::as_str) == Some("--all") {
                Store::load()?.tokens.keys().cloned().collect()
            } else {
                vec![index_url.to_string()]
            };
            rotate(&urls)
        }
        Some("configure") => config::configure(),
        Some("migrate") => match args.get(1).map(String::as_str) {
            None => migrate(false),
            Some("--keep") => migrate(true),
            Some(_) => usage(),
        },
        Some("list") => {
            for url in Store::load()?.tokens.keys() {
                println!("{url}");
            }
            Ok(())
        }
        _ => usage(),
    }
}

fn main() {
    secure::harden();
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().map(String::as_str) == Some("--cargo-plugin") {
        cargo_credential::main(FidoCredential);
        return;
    }
    if let Err(e) = run(&args) {
        eprintln!("error: {e:#}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crates_io_aliases_normalize_to_the_git_index() {
        for url in [
            CRATES_IO_INDEX,
            "https://github.com/rust-lang/crates.io-index/",
            "https://github.com/rust-lang/crates.io-index.git",
            "sparse+https://index.crates.io/",
            "sparse+https://index.crates.io",
        ] {
            assert_eq!(normalize_index_url(url), CRATES_IO_INDEX, "{url}");
        }
    }

    #[test]
    fn sparse_urls_get_a_trailing_slash() {
        assert_eq!(
            normalize_index_url("sparse+https://alt.example/index"),
            "sparse+https://alt.example/index/"
        );
        assert_eq!(
            normalize_index_url("sparse+https://alt.example/index/"),
            "sparse+https://alt.example/index/"
        );
    }

    #[test]
    fn other_urls_are_kept() {
        let url = "https://git.example/index/";
        assert_eq!(normalize_index_url(url), url);
    }
}
