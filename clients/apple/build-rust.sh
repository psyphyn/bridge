#!/bin/bash
# Build the Rust FFI library for Apple platforms.
#
# Usage:
#   ./build-rust.sh              # Build for current macOS architecture
#   ./build-rust.sh --release    # Release build
#   ./build-rust.sh --ios        # Build for iOS (arm64)
#   ./build-rust.sh --universal  # Universal binary (arm64 + x86_64)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
FFI_CRATE="$REPO_ROOT/crates/bridge-ffi"
OUT_DIR="$SCRIPT_DIR/lib"

PROFILE="debug"
TARGETS=()

for arg in "$@"; do
    case $arg in
        --release)
            PROFILE="release"
            ;;
        --ios)
            TARGETS+=("aarch64-apple-ios")
            ;;
        --ios-sim)
            TARGETS+=("aarch64-apple-ios-sim" "x86_64-apple-ios")
            ;;
        --universal)
            TARGETS+=("aarch64-apple-darwin" "x86_64-apple-darwin")
            ;;
    esac
done

# Default: build for current host
if [ ${#TARGETS[@]} -eq 0 ]; then
    TARGETS+=("$(rustc -vV | grep host | cut -d' ' -f2)")
fi

CARGO_FLAGS=""
if [ "$PROFILE" = "release" ]; then
    CARGO_FLAGS="--release"
fi

mkdir -p "$OUT_DIR"

echo "Building bridge-ffi for: ${TARGETS[*]} ($PROFILE)"

for target in "${TARGETS[@]}"; do
    echo "  Building $target..."

    # Ensure target is installed
    rustup target add "$target" 2>/dev/null || true

    cargo build -p bridge-ffi --target "$target" $CARGO_FLAGS

    # Copy the static library
    cp "$REPO_ROOT/target/$target/$PROFILE/libbridge_ffi.a" "$OUT_DIR/libbridge_ffi-$target.a"
done

# If multiple targets, create universal binary with lipo
if [ ${#TARGETS[@]} -gt 1 ]; then
    echo "  Creating universal binary..."
    LIPO_INPUTS=()
    for target in "${TARGETS[@]}"; do
        LIPO_INPUTS+=("$OUT_DIR/libbridge_ffi-$target.a")
    done
    lipo -create "${LIPO_INPUTS[@]}" -output "$OUT_DIR/libbridge_ffi.a"
    echo "  Universal binary: $OUT_DIR/libbridge_ffi.a"
else
    cp "$OUT_DIR/libbridge_ffi-${TARGETS[0]}.a" "$OUT_DIR/libbridge_ffi.a"
fi

# Copy the C header
cp "$SCRIPT_DIR/Bridge/Sources/BridgeCore/bridge_ffi.h" "$OUT_DIR/"

echo "Done. Output: $OUT_DIR/"
ls -lh "$OUT_DIR/libbridge_ffi.a"
