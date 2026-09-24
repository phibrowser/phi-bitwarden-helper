#!/usr/bin/env bash
# Rebuild PhiBitwardenHelper (SDK feature) and refresh the copy Phi bundles.
#
# Phi's Xcode project now bundles the helper from phibrowser-mac/Vendor via its
# "Copy Bitwarden Helper" copy phase (it code-signs it with the app identity).
# So the durable step is refreshing that vendored binary; the next Phi build
# picks it up. For quick iteration WITHOUT rebuilding Phi, this also hot-swaps
# the binary into the newest built app bundle and clears the stale helper.
#
#   ./install-into-phi.sh            # vendor + hot-swap into newest Phi Canary
#   ./install-into-phi.sh --vendor   # only refresh the vendored binary

set -euo pipefail
cd "$(dirname "$0")"
export PATH="$HOME/.cargo/bin:$PATH"

PHI_MAC="$HOME/Phi/phibrowser-mac"
VENDOR="$PHI_MAC/Vendor/PhiBitwardenHelper"

# The SDK checkout this links against, and the pin the README documents.
SDK_DIR="../sdk-internal"
SDK_BASE="7fd530e4"
SDK_BRANCH="phi/rust-v3.0.0-patched"

# GPLv3 §6 guard, checked BEFORE the build so it fails fast. The vendored
# offer names sdk-patches/ as Corresponding Source, so the series must
# reconstruct the exact SDK tree this binary links — a Phi patch that lands on
# the branch without being exported would otherwise ship a binary nobody can
# rebuild from published source. --no-signature keeps the check independent of
# the local git version, which format-patch otherwise stamps on every patch.
# Regenerate with:
#   git -C ../sdk-internal format-patch --no-signature $SDK_BASE..$SDK_BRANCH -o sdk-patches
echo "==> verifying sdk-patches/ matches $SDK_BRANCH"
if ! git -C "$SDK_DIR" rev-parse --verify -q "$SDK_BASE^{commit}" >/dev/null \
  || ! git -C "$SDK_DIR" rev-parse --verify -q "$SDK_BRANCH^{commit}" >/dev/null; then
  echo "error: $SDK_DIR has no $SDK_BASE or $SDK_BRANCH — is the SDK checkout current?" >&2
  exit 1
fi
PATCH_CHECK_DIR="$(mktemp -d)"
trap 'rm -rf "$PATCH_CHECK_DIR"' EXIT
git -C "$SDK_DIR" format-patch --no-signature "$SDK_BASE..$SDK_BRANCH" -o "$PATCH_CHECK_DIR" >/dev/null
if ! diff -r "$PATCH_CHECK_DIR" sdk-patches >/dev/null 2>&1; then
  echo "error: sdk-patches/ is out of date with $SDK_BRANCH — the shipped source" >&2
  echo "       offer would be incomplete (GPLv3 §6). Regenerate it with:" >&2
  echo "         rm -f sdk-patches/*.patch" >&2
  echo "         git -C $SDK_DIR format-patch --no-signature $SDK_BASE..$SDK_BRANCH -o sdk-patches" >&2
  diff -r "$PATCH_CHECK_DIR" sdk-patches >&2 || true
  exit 1
fi

echo "==> building PhiBitwardenHelper (--features bitwarden-sdk)"
cargo build --release --features bitwarden-sdk
BIN="target/release/PhiBitwardenHelper"

echo "==> refreshing vendored binary: $VENDOR"
mkdir -p "$(dirname "$VENDOR")"
cp -f "$BIN" "$VENDOR"

# GPLv3 §6: the app must ship the full license text and a Corresponding Source
# offer next to the binary. Vendor both so the Xcode copy phase bundles them;
# the offer is stamped with the exact commit this binary was built from
# ("-dirty" must never appear in a shipped build — rebuild from a clean tree).
COMMIT="$(git rev-parse --short HEAD)"
git diff --quiet HEAD || COMMIT="$COMMIT-dirty"
VERSION="$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)"
echo "==> refreshing vendored GPL material (build $COMMIT, v$VERSION)"
cp -f LICENSE "$(dirname "$VENDOR")/PhiBitwardenHelper-LICENSE.txt"
sed -e "s/@HELPER_COMMIT@/$COMMIT/" -e "s/@HELPER_VERSION@/$VERSION/" \
  dist/SOURCE-OFFER.txt > "$(dirname "$VENDOR")/PhiBitwardenHelper-SOURCE-OFFER.txt"

if [[ "${1:-}" == "--vendor" ]]; then
  echo "==> done. Rebuild Phi in Xcode to bundle it."
  exit 0
fi

# Hot-swap into the newest built app bundle (skip a full Phi rebuild).
APP="$(ls -dt \
  "$HOME"/Library/Developer/Xcode/DerivedData/Phi-*/Build/Products/Debug-Canary/"Phi Canary.app" \
  /Applications/"Phi Canary.app" /Applications/Phi.app 2>/dev/null | head -1 || true)"
if [[ -n "$APP" && -d "$APP" ]]; then
  echo "==> hot-swapping into: $APP"
  cp -f "$BIN" "$APP/Contents/Helpers/PhiBitwardenHelper"
  codesign --force --sign - "$APP/Contents/Helpers/PhiBitwardenHelper"
  pkill -f "Helpers/PhiBitwardenHelper" 2>/dev/null || true
  echo "==> done. In Phi, reopen Settings ▸ General to refresh the card."
else
  echo "==> no built app found to hot-swap; vendored binary refreshed for next Phi build."
fi
