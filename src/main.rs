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

mod config;
mod fido;
mod store;

use anyhow::{Result, bail};
use cargo_credential::{
    Action, CacheControl, Credential, CredentialResponse, Error, RegistryInfo, Secret,
};
use fido::Authenticator;
use std::io::{IsTerminal, Read};
use store::{CredentialRecord, Store};
use zeroize::Zeroizing;

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
                let token = cargo_credential::read_token(options, registry)?;
                login(registry.index_url, token.as_deref().expose())?;
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
    let auth = Authenticator::open()?;

    let (cred, pin) = match store.credential.clone() {
        Some(cred) => {
            let pin = fido::prompt_pin(cred.uv)?;
            (cred, pin)
        }
        None => {
            // First use: register a credential on the key. Use the PIN if the
            // key has one, so the token also requires something you know.
            let uv = auth.has_pin()?;
            let pin = fido::prompt_pin(uv)?;
            let cred = CredentialRecord {
                id: auth.enroll(pin.as_deref().map(String::as_str))?,
                uv,
            };
            store.credential = Some(cred.clone());
            eprintln!("Touch your FIDO key again to encrypt the token.");
            (cred, pin)
        }
    };

    store.seal(
        &auth,
        &cred,
        pin.as_deref().map(String::as_str),
        index_url,
        token,
    )?;
    store.save()?;
    eprintln!(
        "Token for {index_url} stored in {}",
        store::path()?.display()
    );
    Ok(())
}

fn get(index_url: &str) -> Result<Option<Zeroizing<String>>> {
    let store = Store::load()?;
    let (Some(cred), true) = (&store.credential, store.tokens.contains_key(index_url)) else {
        return Ok(None);
    };
    let auth = Authenticator::open()?;
    let pin = fido::prompt_pin(cred.uv)?;
    store.unseal(&auth, pin.as_deref().map(String::as_str), index_url)
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
    let Some(cred) = store.credential.clone() else {
        bail!("no tokens stored");
    };
    if let Some(missing) = index_urls.iter().find(|u| !store.tokens.contains_key(*u)) {
        bail!("no token stored for {missing}");
    }
    let auth = Authenticator::open()?;
    let pin = fido::prompt_pin(cred.uv)?;
    let pin = pin.as_deref().map(String::as_str);

    for url in index_urls {
        eprintln!("Rotating salt for {url}.");
        store.rotate(&auth, pin, url)?;
    }
    // Save once at the end: if anything fails, the old entries stay intact.
    store.save()?;
    eprintln!("Rotated {} token(s).", index_urls.len());
    Ok(())
}

fn read_token_from_stdin() -> Result<Zeroizing<String>> {
    let token = if std::io::stdin().is_terminal() {
        Zeroizing::new(rpassword::prompt_password("Paste your cargo API token: ")?)
    } else {
        let mut buf = Zeroizing::new(String::new());
        std::io::stdin().read_to_string(&mut buf)?;
        buf
    };
    Ok(Zeroizing::new(token.trim().to_string()))
}

fn usage() -> ! {
    eprintln!(
        "usage: cargo-credential-fido <login|get|logout> [INDEX_URL]\n       \
         cargo-credential-fido rotate [INDEX_URL|--all]\n       \
         cargo-credential-fido list\n       \
         cargo-credential-fido configure\n\n\
         INDEX_URL defaults to {CRATES_IO_INDEX} (crates.io)."
    );
    std::process::exit(2);
}

fn run(args: &[String]) -> Result<()> {
    let index_url = args.get(1).map(String::as_str).unwrap_or(CRATES_IO_INDEX);
    match args.first().map(String::as_str) {
        Some("login") => login(index_url, &read_token_from_stdin()?),
        Some("get") => match get(index_url)? {
            Some(token) => {
                println!("{}", token.as_str());
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
