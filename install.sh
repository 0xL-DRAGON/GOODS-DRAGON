#!/bin/bash
# GOODS-DRAGON One-Line Installer
# Team: L-DRAGON | Owner: 0xL-DRAGON

set -e
echo "🐉 Installing GOODS-DRAGON v2.0.0..."

# Detect OS
if [ -d "/data/data/com.termux/files/usr" ]; then
    echo "[*] Termux detected"
    pkg update -y && pkg install python git -y
    PREFIX="/data/data/com.termux/files/usr"
else
    echo "[*] Linux/macOS detected"
    PREFIX="/usr/local"
fi

# Clone and install
git clone https://github.com/0xL-DRAGON/GOODS-DRAGON.git ~/GOODS-DRAGON
cd ~/GOODS-DRAGON
pip install -r requirements.txt
ln -sf ~/GOODS-DRAGON/dragon $PREFIX/bin/dragon
chmod +x ~/GOODS-DRAGON/dragon

echo ""
echo "✅ GOODS-DRAGON installed successfully!"
echo "   Run: dragon"
echo "   Help: dragon -h"
