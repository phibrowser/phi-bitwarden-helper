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
