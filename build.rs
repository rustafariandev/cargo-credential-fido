//! Link settings that cannot be made from code.

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    let target = |key| std::env::var(key).unwrap_or_default();
    if target("CARGO_CFG_TARGET_OS") == "windows" && target("CARGO_CFG_TARGET_ENV") == "msvc" {
        // webauthn.dll is a load-time import, resolved before main runs, and
        // the default search order looks in the executable's directory
        // first: a webauthn.dll planted next to the binary would be loaded.
        // Resolve imports from System32 only (LOAD_LIBRARY_SEARCH_SYSTEM32).
        println!("cargo:rustc-link-arg-bins=/DEPENDENTLOADFLAG:0x800");
    }
}
