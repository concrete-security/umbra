#!/bin/bash
set -e

echo "Setting up WASM toolchain for macOS..."

if ! command -v brew &> /dev/null; then
    echo "Error: Homebrew is required but not installed."
    echo "Install it from https://brew.sh"
    exit 1
fi

echo "Installing LLVM with WASM support..."
brew install llvm

LLVM_PATH=$(brew --prefix llvm)
export PATH="$LLVM_PATH/bin:$PATH"

echo "Verifying WASM target support..."
if "$LLVM_PATH/bin/clang" --target=wasm32-unknown-unknown -c -x c /dev/null -o /dev/null 2>/dev/null; then
    echo "✓ WASM target is supported"
else
    echo "✗ WASM target is not supported. You may need to build LLVM with WASM support."
    exit 1
fi

echo ""
echo "Setup complete! To use the WASM toolchain, run:"
echo "  export PATH=\"$LLVM_PATH/bin:\$PATH\""
echo ""
echo "Or add it to your shell profile:"
echo "  echo 'export PATH=\"$LLVM_PATH/bin:\$PATH\"' >> ~/.zshrc"


