#!/usr/bin/env bash
# End-to-end tests against a software FIDO2 key, virtual-fido
# (https://github.com/rustafariandev/virtual-fido-rs), which shows up as a real
# /dev/hidrawN device:
#
#   scripts/e2e.sh PATH/TO/virtual-fido
#
# Needs sudo (virtual-fido creates /dev/uhid devices, and the hidraw node it gets
# is made accessible to the current user) and python3 with python-fido2 0.9.x (to
# set the PIN). It refuses to run while any other FIDO key is attached, so a PIN
# can never be set on a real key. Stores and cargo files live in a temporary
# directory; the virtual key keeps everything in memory.
set -euo pipefail

vfido=$(realpath "${1:?usage: scripts/e2e.sh PATH/TO/virtual-fido}")
root=$(cd "$(dirname "$0")/.." && pwd)
pin=123456
crates_io=https://github.com/rust-lang/crates.io-index
alt=sparse+https://alt.example/index/

cargo build --manifest-path "$root/Cargo.toml"
export PATH=$root/target/debug:$PATH

work=$(mktemp -d)
cd "$work"
vpid=
trap 'stop_key; rm -rf "$work"' EXIT

# FIDO hidraw devices: report descriptors starting with the FIDO usage page (06 d0 f1).
fido_devices() {
    local d
    for d in /sys/class/hidraw/*; do
        if [[ $(od -An -tx1 -N3 "$d/device/report_descriptor" 2>/dev/null | tr -d ' \n') == 06d0f1 ]]; then
            echo "/dev/$(basename "$d")"
        fi
    done
}

start_key() {
    sudo "$vfido" --store memory --presence auto >>"$work/virtual-fido.log" 2>&1 &
    vpid=$!
    local dev i
    for i in $(seq 100); do
        dev=$(fido_devices)
        [[ -n $dev ]] && break
        sleep 0.1
    done
    if [[ -z $dev ]]; then
        echo "virtual-fido did not create a FIDO device; its log:" >&2
        cat "$work/virtual-fido.log" >&2
        exit 1
    fi
    # Let udev finish with the node before changing its mode, so it is not reset.
    sudo udevadm settle || true
    sudo chmod 0666 "$dev"
    echo "== virtual key at $dev"
}

stop_key() {
    [[ -n $vpid ]] || return 0
    sudo kill "$vpid" 2>/dev/null || true
    wait "$vpid" 2>/dev/null || true
    vpid=
    local i
    for i in $(seq 50); do
        [[ -z $(fido_devices) ]] && return 0
        sleep 0.1
    done
}

set_pin() {
    python3 - "$1" <<'EOF'
import sys
from fido2.hid import CtapHidDevice
from fido2.ctap2 import Ctap2
from fido2.ctap2.pin import ClientPin

devices = list(CtapHidDevice.list_devices())
assert len(devices) == 1, f"expected one FIDO device, found {len(devices)}"
ClientPin(Ctap2(devices[0])).set_pin(sys.argv[1])
EOF
}

step() { echo "-- $*"; }

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

expect_eq() { # actual expected what
    [[ $1 == "$2" ]] || fail "$3: expected '$2', got '$1'"
}

expect_fail() { # what command...
    local what=$1
    shift
    if "$@" >/dev/null 2>"$work/stderr"; then
        fail "$what: succeeded, but should have failed"
    fi
    echo "   (failed as expected: $(tail -1 "$work/stderr"))"
}

# Send one request through the cargo credential protocol and print the response.
plugin_get() { # index_url
    printf '{"v":1,"registry":{"index-url":"%s","name":"crates-io"},"kind":"get","operation":"read","args":[]}\n' "$1" |
        cargo-credential-fido --cargo-plugin | tail -1
}

if [[ -n $(fido_devices) ]]; then
    echo "refusing to run: FIDO devices are attached ($(fido_devices | xargs)); unplug them first" >&2
    exit 1
fi
sudo -v

export CARGO_HOME=$work/cargo-home
unset CARGO_CREDENTIAL_FIDO_PIN

echo "== key without a PIN"
start_key
export CARGO_CREDENTIAL_FIDO_STORE=$work/nopin.json

step "login and get"
printf 'tok-crates\n' | cargo-credential-fido login
expect_eq "$(cargo-credential-fido get)" tok-crates "crates.io token"
printf 'tok-alt' | cargo-credential-fido login "$alt"
expect_eq "$(cargo-credential-fido get "$alt")" tok-alt "alt registry token"
expect_eq "$(cargo-credential-fido list | sort | xargs)" "$crates_io $alt" "list"
expect_eq "$(cargo-credential-fido get sparse+https://index.crates.io/)" tok-crates "crates.io via its sparse URL"
expect_eq "$(cargo-credential-fido get "${alt%/}")" tok-alt "alt registry without the trailing slash"
expect_eq "$(stat -c %a "$CARGO_CREDENTIAL_FIDO_STORE")" 600 "store file mode"
grep -q '"uv": *false' "$CARGO_CREDENTIAL_FIDO_STORE" || fail "store should not require a PIN"
! grep -q tok- "$CARGO_CREDENTIAL_FIDO_STORE" || fail "plaintext token in the store"

step "empty and unknown tokens"
expect_fail "empty token" sh -c 'printf "  \n" | cargo-credential-fido login'
expect_fail "get unknown registry" cargo-credential-fido get https://unknown.example/index

step "rotate"
before=$(sha256sum <"$CARGO_CREDENTIAL_FIDO_STORE")
cargo-credential-fido rotate --all
[[ $(sha256sum <"$CARGO_CREDENTIAL_FIDO_STORE") != "$before" ]] || fail "rotate did not change the store"
expect_eq "$(cargo-credential-fido get)" tok-crates "crates.io token after rotate"
expect_eq "$(cargo-credential-fido get "$alt")" tok-alt "alt token after rotate"
expect_fail "rotate unknown registry" cargo-credential-fido rotate https://unknown.example/index

step "tampered ciphertext"
cp "$CARGO_CREDENTIAL_FIDO_STORE" "$work/good.json"
python3 -I - "$CARGO_CREDENTIAL_FIDO_STORE" "$crates_io" <<'EOF'
import json, sys
path, url = sys.argv[1:]
store = json.load(open(path))
ct = bytearray.fromhex(store["tokens"][url]["ciphertext"])
ct[0] ^= 1
store["tokens"][url]["ciphertext"] = ct.hex()
json.dump(store, open(path, "w"))
EOF
expect_fail "get with tampered ciphertext" cargo-credential-fido get
cp "$work/good.json" "$CARGO_CREDENTIAL_FIDO_STORE"

step "cargo credential protocol"
response=$(plugin_get "$crates_io")
[[ $response == *'"token":"tok-crates"'* ]] || fail "protocol get: $response"
response=$(plugin_get https://unknown.example/index)
[[ $response == *'"Err"'* ]] || fail "protocol get of unknown registry: $response"

step "logout"
cargo-credential-fido logout "$alt"
expect_fail "get after logout" cargo-credential-fido get "$alt"
expect_fail "logout twice" cargo-credential-fido logout "$alt"
expect_eq "$(cargo-credential-fido list)" "$crates_io" "list after logout"

step "configure"
mkdir -p "$CARGO_HOME"
rm -f "$CARGO_HOME/config.toml"
cargo-credential-fido configure
grep -q 'global-credential-providers = \["cargo:token", "cargo-credential-fido"\]' "$CARGO_HOME/config.toml" ||
    fail "configure without providers should keep cargo:token: $(cat "$CARGO_HOME/config.toml")"
printf '[registry]\nglobal-credential-providers = ["cargo:token"]\n' >"$work/linked.toml"
ln -sf "$work/linked.toml" "$CARGO_HOME/config.toml"
cargo-credential-fido configure
[[ -L $CARGO_HOME/config.toml ]] || fail "configure replaced a symlinked config"
grep -q cargo-credential-fido "$work/linked.toml" || fail "configure did not write through the symlink"
rm "$CARGO_HOME/config.toml"
printf '# keep me\n[registry]\nglobal-credential-providers = ["cargo:token"]\n' >"$CARGO_HOME/config.toml"
cargo-credential-fido configure
cargo-credential-fido configure
grep -q '# keep me' "$CARGO_HOME/config.toml" || fail "configure dropped a comment"
grep -q 'global-credential-providers = \["cargo:token", "cargo-credential-fido"\]' "$CARGO_HOME/config.toml" ||
    fail "configure: $(cat "$CARGO_HOME/config.toml")"

step "cargo login / logout through the provider"
cargo logout
expect_eq "$(cargo-credential-fido list)" "" "list after cargo logout"
cargo login tok-cargo
expect_eq "$(cargo-credential-fido get)" tok-cargo "token stored by cargo login"
[[ ! -e $CARGO_HOME/credentials.toml ]] || ! grep -q tok-cargo "$CARGO_HOME/credentials.toml" ||
    fail "cargo login wrote a plaintext token"

step "migrate"
export CARGO_CREDENTIAL_FIDO_STORE=$work/migrate.json
cat >>"$CARGO_HOME/config.toml" <<EOF
[registries.foo]
index = "$alt"
EOF
cat >"$CARGO_HOME/credentials.toml" <<'EOF'
# credentials
[registry]
token = "tok-plain-crates"

[registries.foo]
token = "tok-plain-foo"

[registries.bar]
token = "tok-plain-bar"
EOF
cargo-credential-fido migrate --keep
grep -q tok-plain-crates "$CARGO_HOME/credentials.toml" || fail "migrate --keep removed a token"
rm "$CARGO_CREDENTIAL_FIDO_STORE"
cargo-credential-fido migrate
expect_eq "$(cargo-credential-fido get)" tok-plain-crates "migrated crates.io token"
expect_eq "$(cargo-credential-fido get "$alt")" tok-plain-foo "migrated foo token"
! grep -q 'tok-plain-crates\|tok-plain-foo' "$CARGO_HOME/credentials.toml" ||
    fail "migrate left plaintext tokens: $(cat "$CARGO_HOME/credentials.toml")"
grep -q tok-plain-bar "$CARGO_HOME/credentials.toml" || fail "migrate removed the unresolvable bar token"
grep -q '# credentials' "$CARGO_HOME/credentials.toml" || fail "migrate dropped a comment"

step "migrate edge cases"
chmod 600 "$CARGO_HOME/credentials.toml"
printf '[registry]\ntoken = "tok-plain-crates"\n' >>"$CARGO_HOME/credentials.toml"
cargo-credential-fido migrate
expect_eq "$(stat -c %a "$CARGO_HOME/credentials.toml")" 600 "credentials file mode after migrate"
rm "$CARGO_CREDENTIAL_FIDO_STORE"
printf '[registry]\ntoken = ""\n' >"$CARGO_HOME/credentials.toml"
expect_fail "migrate an empty token" cargo-credential-fido migrate
[[ ! -e $CARGO_CREDENTIAL_FIDO_STORE ]] || fail "migrate of an empty token created a store"
# Cargo reads the legacy extensionless file when both exist.
printf '[registry]\ntoken = "tok-legacy"\n' >"$CARGO_HOME/credentials"
cargo-credential-fido migrate
expect_eq "$(cargo-credential-fido get)" tok-legacy "token migrated from the legacy credentials file"
! grep -q tok-legacy "$CARGO_HOME/credentials" || fail "migrate left the legacy token"
rm "$CARGO_HOME/credentials" "$CARGO_HOME/credentials.toml"

echo "== new key, with a PIN set after enrolling"
stop_key
start_key

step "tokens from another key cannot be read"
export CARGO_CREDENTIAL_FIDO_STORE=$work/nopin.json
expect_fail "get with a different key" cargo-credential-fido get

step "enroll without a PIN, then set one"
export CARGO_CREDENTIAL_FIDO_STORE=$work/before-pin.json
printf 'tok-before-pin' | cargo-credential-fido login
set_pin "$pin"
expect_eq "$(cargo-credential-fido get)" tok-before-pin "token sealed before the PIN was set"

step "enroll with the PIN"
export CARGO_CREDENTIAL_FIDO_STORE=$work/pin.json
export CARGO_CREDENTIAL_FIDO_PIN=$pin
printf 'tok-pin' | cargo-credential-fido login
grep -q '"uv": *true' "$CARGO_CREDENTIAL_FIDO_STORE" || fail "store should require the PIN"
expect_eq "$(cargo-credential-fido get)" tok-pin "PIN-protected token"
cargo-credential-fido rotate
expect_eq "$(cargo-credential-fido get)" tok-pin "PIN-protected token after rotate"
CARGO_CREDENTIAL_FIDO_PIN=654321 expect_fail "get with a wrong PIN" cargo-credential-fido get
expect_eq "$(cargo-credential-fido get)" tok-pin "PIN-protected token after a wrong PIN"

echo "== all checks passed"
