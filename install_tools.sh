#!/bin/bash
# =============================================================================
# Bug Bounty Tool Installer (Linux + macOS)
# Installs all required tools via package manager and Go
# Usage: ./install_tools.sh [--with-cicd-scanner]
# =============================================================================

set -euo pipefail

INSTALL_CICD_SCANNER=false
for arg in "$@"; do
    case "$arg" in
        --with-cicd-scanner) INSTALL_CICD_SCANNER=true ;;
    esac
done

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_ok()   { echo -e "${GREEN}[+]${NC} $1"; }
log_err()  { echo -e "${RED}[-]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[!]${NC} $1"; }

echo "============================================="
echo "  Bug Bounty Tool Installer"
echo "  (Linux + macOS compatible)"
echo "============================================="

# Detect OS
OS_TYPE=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)
case "$ARCH" in
    x86_64)  ARCH="amd64" ;;
    aarch64) ARCH="arm64" ;;
    armv6l)  ARCH="armv6" ;;
esac

# Check for Go (needed for most tools)
if ! command -v go &>/dev/null; then
    log_warn "Go not found. Installing..."
    if [ "$OS_TYPE" = "darwin" ]; then
        brew install go 2>/dev/null || { log_err "Install Go manually: https://go.dev/dl/"; exit 1; }
    else
        sudo apt-get update -qq && sudo apt-get install -y -qq golang-go 2>/dev/null || \
        { log_err "Install Go manually: https://go.dev/dl/"; exit 1; }
    fi
fi

# Check for Python 3
if ! command -v python3 &>/dev/null; then
    log_warn "Python3 not found. Installing..."
    if [ "$OS_TYPE" = "darwin" ]; then
        brew install python3
    else
        sudo apt-get update -qq && sudo apt-get install -y -qq python3 python3-pip
    fi
fi

# Check for jq
if ! command -v jq &>/dev/null; then
    log_warn "jq not found. Installing..."
    if [ "$OS_TYPE" = "darwin" ]; then
        brew install jq
    else
        sudo apt-get install -y -qq jq
    fi
fi

# ─── Go Tools (primary installation method) ────────────────────────────
echo ""
echo "[*] Installing tools via Go..."

GO_TOOLS=(
    "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    "github.com/projectdiscovery/httpx/cmd/httpx@latest"
    "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
    "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    "github.com/projectdiscovery/katana/cmd/katana@latest"
    "github.com/ffuf/ffuf/v2@latest"
    "github.com/lc/gau/v2/cmd/gau@latest"
    "github.com/hahwul/dalfox/v2@latest"
    "github.com/tomnomnom/anew@latest"
    "github.com/tomnomnom/qsreplace@latest"
    "github.com/tomnomnom/assetfinder@latest"
    "github.com/tomnomnom/gf@latest"
    "github.com/tomnomnom/waybackurls@latest"
    "github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest"
    "github.com/haccer/subjack@latest"
)

GO_TOOL_NAMES=(
    "subfinder"
    "httpx"
    "dnsx"
    "nuclei"
    "katana"
    "ffuf"
    "gau"
    "dalfox"
    "anew"
    "qsreplace"
    "assetfinder"
    "gf"
    "waybackurls"
    "interactsh-client"
    "subjack"
)

for i in "${!GO_TOOLS[@]}"; do
    tool_name="${GO_TOOL_NAMES[$i]}"
    tool_path="${GO_TOOLS[$i]}"
    if command -v "$tool_name" &>/dev/null; then
        log_ok "$tool_name already installed"
    else
        echo "    Installing $tool_name..."
        if go install "$tool_path" 2>/dev/null; then
            log_ok "$tool_name installed successfully"
        else
            log_err "$tool_name failed to install"
        fi
    fi
done

# ─── Mobile Security Tools ─────────────────────────────────────────────
echo ""
echo "[*] Installing mobile security tools..."

# apktool
if command -v apktool &>/dev/null; then
    log_ok "apktool already installed"
else
    echo "    Installing apktool..."
    if [ "$OS_TYPE" = "darwin" ]; then
        brew install apktool 2>/dev/null && log_ok "apktool installed" || log_err "apktool failed"
    else
        sudo apt-get install -y -qq apktool 2>/dev/null && log_ok "apktool installed" || log_err "apktool failed — install from https://ibotpeaches.github.io/Apktool/"
    fi
fi

# jadx
if command -v jadx &>/dev/null; then
    log_ok "jadx already installed"
else
    echo "    Installing jadx..."
    if [ "$OS_TYPE" = "darwin" ]; then
        brew install jadx 2>/dev/null && log_ok "jadx installed" || log_err "jadx failed"
    else
        JADX_VERSION=$(curl -sI https://github.com/skylot/jadx/releases/latest | grep -i '^location:' | grep -oP 'v[\d.]+' || echo "v1.5.1")
        JADX_URL="https://github.com/skylot/jadx/releases/download/${JADX_VERSION}/jadx-${JADX_VERSION#v}-no-jdk-linux-amd64.zip"
        if curl -sL "$JADX_URL" -o /tmp/jadx.zip && \
           unzip -qo /tmp/jadx.zip -d /tmp/jadx && \
           { sudo mv /tmp/jadx/bin/jadx /usr/local/bin/jadx 2>/dev/null || mv /tmp/jadx/bin/jadx "$HOME/bin/jadx"; }; then
            rm -rf /tmp/jadx.zip /tmp/jadx
            log_ok "jadx installed"
        else
            rm -rf /tmp/jadx.zip /tmp/jadx
            log_err "jadx failed — install from https://github.com/skylot/jadx"
        fi
    fi
fi

# Frida + objection (Python)
if command -v frida &>/dev/null; then
    log_ok "frida already installed"
else
    echo "    Installing frida-tools + objection..."
    pip3 install -q frida-tools objection 2>/dev/null && \
        log_ok "frida-tools + objection installed" || \
        log_err "frida/objection failed — pip3 install frida-tools objection"
fi

# ─── Source Code Audit Tools ──────────────────────────────────────────
echo ""
echo "[*] Installing source code audit tools..."

# Semgrep
if command -v semgrep &>/dev/null; then
    log_ok "semgrep already installed"
else
    echo "    Installing semgrep..."
    pip3 install -q semgrep 2>/dev/null && log_ok "semgrep installed" || log_err "semgrep failed"
fi

# trufflehog
if command -v trufflehog &>/dev/null; then
    log_ok "trufflehog already installed"
else
    echo "    Installing trufflehog..."
    if [ "$OS_TYPE" = "darwin" ]; then
        brew install trufflehog 2>/dev/null && log_ok "trufflehog installed" || log_err "trufflehog failed"
    else
        curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin 2>/dev/null && \
            log_ok "trufflehog installed" || log_err "trufflehog failed"
    fi
fi

# gitleaks
if command -v gitleaks &>/dev/null; then
    log_ok "gitleaks already installed"
else
    echo "    Installing gitleaks..."
    go install github.com/gitleaks/gitleaks/v8@latest 2>/dev/null && \
        log_ok "gitleaks installed" || log_err "gitleaks failed"
fi

# gosec (Go SAST)
if command -v gosec &>/dev/null; then
    log_ok "gosec already installed"
else
    echo "    Installing gosec..."
    go install github.com/securego/gosec/v2/cmd/gosec@latest 2>/dev/null && \
        log_ok "gosec installed" || log_err "gosec failed"
fi

# bandit (Python SAST)
if python3 -c "import bandit" 2>/dev/null; then
    log_ok "bandit already installed"
else
    echo "    Installing bandit..."
    pip3 install -q bandit 2>/dev/null && log_ok "bandit installed" || log_err "bandit failed"
fi

# ─── nmap (system package) ─────────────────────────────────────────────
echo ""
echo "[*] Checking nmap..."
if command -v nmap &>/dev/null; then
    log_ok "nmap already installed"
else
    echo "    Installing nmap..."
    if [ "$OS_TYPE" = "darwin" ]; then
        brew install nmap 2>/dev/null && log_ok "nmap installed" || log_err "nmap failed"
    else
        sudo apt-get install -y -qq nmap 2>/dev/null && log_ok "nmap installed" || log_err "nmap failed"
    fi
fi

# ─── sisakulint (GitHub Actions SAST) ──────────────────────────────────
echo ""
echo "[*] Installing sisakulint..."
SISAKULINT_LATEST=$(curl -sI https://github.com/sisaku-security/sisakulint/releases/latest | grep -i '^location:' | grep -oP 'v[\d.]+' || true)
SISAKULINT_LATEST="${SISAKULINT_LATEST#v}"
SISAKULINT_CURRENT=""
if command -v sisakulint &>/dev/null; then
    SISAKULINT_CURRENT=$(sisakulint -version 2>&1 | grep -oP '[\d]+\.[\d]+\.[\d]+' || true)
fi
if [ -n "$SISAKULINT_CURRENT" ] && [ "$SISAKULINT_CURRENT" = "$SISAKULINT_LATEST" ]; then
    log_ok "sisakulint v${SISAKULINT_CURRENT} already up to date"
elif [ -n "$SISAKULINT_LATEST" ]; then
    SISAKULINT_URL="https://github.com/sisaku-security/sisakulint/releases/download/v${SISAKULINT_LATEST}/sisakulint_${SISAKULINT_LATEST}_${OS_TYPE}_${ARCH}.tar.gz"
    echo "    Downloading sisakulint v${SISAKULINT_LATEST}..."
    if curl -sL "$SISAKULINT_URL" -o /tmp/sisakulint.tar.gz && \
       tar -xzf /tmp/sisakulint.tar.gz -C /tmp/ && \
       { mv /tmp/sisakulint /usr/local/bin/sisakulint 2>/dev/null || \
         sudo mv /tmp/sisakulint /usr/local/bin/sisakulint; }; then
        rm -f /tmp/sisakulint.tar.gz
        log_ok "sisakulint v${SISAKULINT_LATEST} installed"
    else
        rm -f /tmp/sisakulint.tar.gz /tmp/sisakulint
        log_err "sisakulint failed — download from: https://github.com/sisaku-security/sisakulint/releases"
    fi
else
    log_warn "Could not fetch sisakulint version"
fi

# ─── cicd_scanner (optional) ──────────────────────────────────────────
if [ "$INSTALL_CICD_SCANNER" = true ]; then
    SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
    CICD_SCANNER_SRC="$SCRIPT_DIR/tools/cicd_scanner.sh"
    if [ -f "$CICD_SCANNER_SRC" ]; then
        INSTALL_DIR="/usr/local/bin"
        if cp "$CICD_SCANNER_SRC" "$INSTALL_DIR/cicd_scanner" 2>/dev/null || \
           sudo cp "$CICD_SCANNER_SRC" "$INSTALL_DIR/cicd_scanner"; then
            chmod +x "$INSTALL_DIR/cicd_scanner" 2>/dev/null || sudo chmod +x "$INSTALL_DIR/cicd_scanner"
            log_ok "cicd_scanner installed"
        else
            mkdir -p "$HOME/bin"
            cp "$CICD_SCANNER_SRC" "$HOME/bin/cicd_scanner"
            chmod +x "$HOME/bin/cicd_scanner"
            log_ok "cicd_scanner installed to ~/bin/"
        fi
    fi
else
    log_warn "cicd_scanner skipped (use --with-cicd-scanner to install)"
fi

# ─── Update nuclei templates ──────────────────────────────────────────
echo ""
echo "[*] Updating nuclei templates..."
if command -v nuclei &>/dev/null; then
    nuclei -update-templates 2>/dev/null || true
    log_ok "Nuclei templates updated"
fi

# ─── Ensure Go bin is in PATH ─────────────────────────────────────────
GOPATH="${GOPATH:-$HOME/go}"
if [[ ":$PATH:" != *":$GOPATH/bin:"* ]]; then
    log_warn "Add Go bin to your PATH:"
    echo "    export PATH=\$PATH:$GOPATH/bin"
    echo "    # Add to ~/.bashrc or ~/.zshrc for persistence"
fi

# ─── Verification ─────────────────────────────────────────────────────
echo ""
echo "============================================="
echo "[*] Installation Verification"
echo "============================================="

ALL_TOOLS=(subfinder httpx dnsx nuclei katana ffuf nmap gau dalfox anew qsreplace assetfinder gf waybackurls interactsh-client subjack sisakulint apktool jadx frida objection semgrep trufflehog gitleaks gosec)
INSTALLED=0
MISSING=0

for tool in "${ALL_TOOLS[@]}"; do
    if command -v "$tool" &>/dev/null; then
        log_ok "$tool: $(which "$tool")"
        ((++INSTALLED))
    else
        log_err "$tool: NOT FOUND"
        ((++MISSING))
    fi
done

echo ""
echo "============================================="
echo "  Installed: $INSTALLED / ${#ALL_TOOLS[@]}"
[ "$MISSING" -gt 0 ] && echo "  Missing: $MISSING (check errors above)"
echo "============================================="
