#!/usr/bin/env bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "=== Installing system dependencies ==="
if command -v apt-get &>/dev/null; then
    sudo apt-get install -y cmake g++ libboost-all-dev graphviz git
elif command -v brew &>/dev/null; then
    brew install cmake boost graphviz git
else
    echo "WARNING: Could not detect apt-get or brew. Install cmake, g++, boost, graphviz, and git manually."
fi

echo "=== Installing Python packages ==="
pip install -r requirements.txt

echo "=== Building FlexFringe ==="
if [ -f "FlexFringe/flexfringe" ]; then
    echo "FlexFringe binary already exists, skipping build."
else
    TMP_FF=$(mktemp -d)
    git clone https://github.com/tudelft-cda-lab/FlexFringe "$TMP_FF"
    mkdir -p "$TMP_FF/build"
    cmake -S "$TMP_FF" -B "$TMP_FF/build" -DCMAKE_BUILD_TYPE=Release
    cmake --build "$TMP_FF/build" --parallel "$(nproc 2>/dev/null || sysctl -n hw.logicalcpu)"
    mkdir -p FlexFringe
    cp "$TMP_FF/build/flexfringe" FlexFringe/flexfringe
    rm -rf "$TMP_FF"
    echo "FlexFringe built successfully."
fi

echo "=== Setting up FlexFringe config ==="
mkdir -p FlexFringe/ini
cp spdfa-config.ini FlexFringe/ini/spdfa-config.ini

echo "=== Decompressing alert files ==="
find alerts/ -type f -name '*.gz' -exec gunzip -k {} \; 2>/dev/null || true

echo ""
echo "=== Setup complete ==="
echo "Run SAGE with:"
echo "  python sage.py alerts/cptc-2017/ exp-2017 --dataset cptc"
echo "  python sage.py alerts/cptc-2018/ exp-2018 -t 2.0 -w 200 --dataset cptc"
echo "  python sage.py alerts/ccdc/ exp-ccdc --dataset other --keep-files"
