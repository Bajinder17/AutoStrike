#!/bin/bash
# Gemini Bug Bounty — install context files into ~/.gemini/
# Equivalent of the Claude Code installer, adapted for Gemini CLI

set -e

REPO_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "╔══════════════════════════════════════════════╗"
echo "║   Gemini Bug Bounty — Installer              ║"
echo "╚══════════════════════════════════════════════╝"
echo ""

# ─── Step 1: Install GEMINI.md (global context) ──────────────────────────
GEMINI_DIR="${HOME}/.gemini"
mkdir -p "${GEMINI_DIR}"

# Check if user already has a global GEMINI.md
if [ -f "${GEMINI_DIR}/GEMINI.md" ]; then
    echo "[!] Existing ~/.gemini/GEMINI.md found."
    read -p "    Overwrite? (y/N): " overwrite
    if [[ ! "$overwrite" =~ ^[Yy]$ ]]; then
        echo "    Skipping global GEMINI.md — keeping existing."
        echo "    You can manually merge from: ${REPO_DIR}/GEMINI.md"
    else
        cp "${REPO_DIR}/GEMINI.md" "${GEMINI_DIR}/GEMINI.md"
        echo "✓ Installed global GEMINI.md to ${GEMINI_DIR}/GEMINI.md"
    fi
else
    cp "${REPO_DIR}/GEMINI.md" "${GEMINI_DIR}/GEMINI.md"
    echo "✓ Installed global GEMINI.md to ${GEMINI_DIR}/GEMINI.md"
fi

# ─── Step 2: Create symlink for project-level context ────────────────────
echo ""
echo "[*] Setting up project-level context..."

# The GEMINI.md in the repo root serves as project-level context when
# you run `gemini` from inside this directory. This is automatic.
echo "✓ Project GEMINI.md is already in repo root (loaded automatically)"

# ─── Step 3: Copy skill reference docs ───────────────────────────────────
echo ""
echo "[*] Installing skill reference files..."

CONTEXT_DIR="${GEMINI_DIR}/context"
mkdir -p "${CONTEXT_DIR}"

# Copy key reference files for global access
for skill_dir in skills/*/; do
    skill_name=$(basename "$skill_dir")
    mkdir -p "${CONTEXT_DIR}/skills/${skill_name}"
    if [ -f "${skill_dir}SKILL.md" ]; then
        cp "${skill_dir}SKILL.md" "${CONTEXT_DIR}/skills/${skill_name}/SKILL.md"
        echo "  ✓ Skill: ${skill_name}"
    fi
done

# Copy the master SKILL.md
cp "${REPO_DIR}/SKILL.md" "${CONTEXT_DIR}/SKILL.md"
echo "  ✓ Master SKILL.md"

# Copy command docs
mkdir -p "${CONTEXT_DIR}/commands"
for cmd_file in commands/*.md; do
    cmd_name=$(basename "$cmd_file")
    cp "$cmd_file" "${CONTEXT_DIR}/commands/${cmd_name}"
done
echo "  ✓ Command docs ($(ls commands/*.md | wc -l) files)"

# Copy agent docs
mkdir -p "${CONTEXT_DIR}/agents"
for agent_file in agents/*.md; do
    agent_name=$(basename "$agent_file")
    cp "$agent_file" "${CONTEXT_DIR}/agents/${agent_name}"
done
echo "  ✓ Agent docs ($(ls agents/*.md | wc -l) files)"

# Copy rules
mkdir -p "${CONTEXT_DIR}/rules"
for rule_file in rules/*.md; do
    rule_name=$(basename "$rule_file")
    cp "$rule_file" "${CONTEXT_DIR}/rules/${rule_name}"
done
echo "  ✓ Rules ($(ls rules/*.md | wc -l) files)"

echo ""
echo "════════════════════════════════════════════════"
echo "✓ Installation complete!"
echo ""
echo "Files installed to:"
echo "  Global context:  ${GEMINI_DIR}/GEMINI.md"
echo "  Reference docs:  ${CONTEXT_DIR}/"
echo ""
echo "────────────────────────────────────────────────"
echo "Optional: Burp Suite MCP Integration"
echo "────────────────────────────────────────────────"
echo ""
echo "Connect to PortSwigger's Burp MCP server for live HTTP traffic visibility."
echo "See mcp/burp-mcp-client/README.md for setup instructions."
echo ""

# ─── Step 4: Gemini CLI settings.json (optional MCP) ─────────────────────
SETTINGS_FILE="${GEMINI_DIR}/settings.json"
if [ ! -f "$SETTINGS_FILE" ]; then
    cat > "$SETTINGS_FILE" << 'EOF'
{
  "theme": "Default",
  "selectedAuthType": "gemini-api-key"
}
EOF
    echo "✓ Created ${SETTINGS_FILE} (default settings)"
fi

echo ""
echo "Start hunting:"
echo "  cd $(pwd)"
echo "  gemini"
echo '  "recon target.com"'
echo '  "hunt target.com"'
echo ""
