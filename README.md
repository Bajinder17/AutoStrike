

<div align="center">

<img src="https://img.shields.io/badge/v4.1.0--gemini-Bionic_Hunter-blueviolet?style=for-the-badge" alt="v4.1.0-gemini">

# Gemini Bug Bounty

### Find security vulnerabilities, get paid — with AI doing the heavy lifting

*Your AI hunting partner that remembers past targets, spots vulnerabilities, and writes reports for you.*
<br>
*Ported from [claude-bug-bounty](https://github.com/shuvonsec/claude-bug-bounty) for Google's Gemini CLI*
<br>
<sub>Original by <a href="https://shuvonsec.me">shuvonsec</a> · Gemini port by xennt</sub>

<br>

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=flat-square)](LICENSE)
[![Python 3.8+](https://img.shields.io/badge/Python-3.8+-3776AB.svg?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![Gemini CLI](https://img.shields.io/badge/Gemini_CLI-Plugin-4285F4.svg?style=flat-square&logo=google&logoColor=white)](https://github.com/google-gemini/gemini-cli)

<br>

<a href="#-what-is-this">What Is This?</a>&nbsp;&nbsp;|&nbsp;&nbsp;<a href="#-quick-start">Quick Start</a>&nbsp;&nbsp;|&nbsp;&nbsp;<a href="#-commands">Commands</a>&nbsp;&nbsp;|&nbsp;&nbsp;<a href="#-gemini-vs-claude-differences">Differences</a>&nbsp;&nbsp;|&nbsp;&nbsp;<a href="#-installation">Install</a>&nbsp;&nbsp;|&nbsp;&nbsp;<a href="FAQ.md">FAQ</a>

<br>

```
  17 command triggers  ·  11 AI agent roles  ·  12 skill domains
  20 web2 vuln classes  ·  10 web3 bug classes  ·  12 Android + 10 iOS bug classes
  Source code auditing  ·  Burp MCP  ·  HackerOne MCP  ·  Autonomous Mode
```

</div>

<br>

---

<br>

## What Is This?

**Bug bounty hunting** is when companies pay you real money to find security vulnerabilities in their websites and apps before bad actors do.

**This tool** is a context plugin for [Gemini CLI](https://github.com/google-gemini/gemini-cli) (Google's AI coding assistant) that turns it into a professional bug bounty hunting partner. This is a **community port** of the excellent [claude-bug-bounty](https://github.com/shuvonsec/claude-bug-bounty) project, adapted for the Gemini CLI ecosystem.

**In plain terms:**
- You give it a target website
- It automatically scans the site, finds vulnerabilities, validates they're real, and writes a professional report
- You can even put it on autopilot and let it hunt on its own while you sleep

**Who is it for?**
- Security researchers who want to move faster
- Bug bounty hunters who are tired of the manual grind
- People who have **Gemini Pro** tokens but not Claude tokens

<br>

---

<br>

## Quick Start

> **Prerequisite:** You need [Gemini CLI](https://github.com/google-gemini/gemini-cli) installed and a Gemini API key.

**Step 1 — Install tools + context**

```bash
git clone https://github.com/YOUR_USERNAME/gemini-bug-bounty.git
cd gemini-bug-bounty
chmod +x install_tools.sh && ./install_tools.sh   # installs scanning tools (subfinder, httpx, nuclei...)
chmod +x install.sh && ./install.sh               # installs AI context into ~/.gemini/
```

**Step 2 — Start hunting**

```bash
gemini                          # open Gemini CLI in your terminal

# Then type naturally:
recon target.com               # step 1: map the target (subdomains, live pages, URLs)
hunt target.com                # step 2: test for vulnerabilities
validate                       # step 3: make sure the finding is real
report                         # step 4: generate a professional submission report
```

**That's the core loop.** Four commands, full workflow.

**Step 3 — Go autonomous**

```bash
autopilot target.com --normal  # AI does the whole thing, pauses for review
pickup target.com              # continue where you left off
intel target.com               # get CVEs + disclosed reports
```

<br>

> **Want to use the Python tools directly?**
> ```bash
> python3 tools/hunt.py --target target.com
> ./tools/recon_engine.sh target.com
> ```

<br>

---

<br>

## Gemini vs Claude: Differences

This port adapts the Claude Code architecture to Gemini CLI's context system:

| Feature | Claude Code | Gemini CLI |
|:---|:---|:---|
| **Instructions file** | `CLAUDE.md` | `GEMINI.md` |
| **Slash commands** | `/recon`, `/hunt`, etc. | Natural language: `recon target.com` |
| **Skills loading** | `~/.claude/skills/` auto-load | `GEMINI.md` references skill files |
| **Commands** | `~/.claude/commands/` | Command docs in `commands/` read on-demand |
| **Agents** | Built-in `model:` routing | Agent roles described in `agents/` docs |
| **Context hierarchy** | Global → Project | Global `~/.gemini/GEMINI.md` → Project `./GEMINI.md` |
| **Hooks** | `hooks.json` events | Not supported — session tips in GEMINI.md |
| **MCP** | Native integration | Gemini CLI MCP support (if available) |

### What's Preserved
- ✅ All 12 skill domains with full content (web2, web3, Android, iOS, source code audit)
- ✅ All 17 command procedures (as reference docs)
- ✅ All 11 agent role definitions
- ✅ All 24 Python/shell tools
- ✅ All hunting rules and reporting rules
- ✅ Wordlists, payloads, docs
- ✅ Memory system (pattern_db, audit_log)
- ✅ MCP integration configs

<br>

---

<br>

## Commands

### The Core 4 (start here)

| Trigger | What It Does | When To Use |
|:---|:---|:---|
| `recon target.com` | Maps the target — subdomains, live pages, APIs, scans | Always first |
| `hunt target.com` | Actively tests for vulnerabilities | After recon |
| `validate` | 7-question check to confirm a finding | Before every report |
| `report` | Generates a professional submission report | After validation |

### Power Commands

| Trigger | What It Does |
|:---|:---|
| `autopilot target.com` | AI runs the full loop automatically |
| `surface target.com` | Ranked list of best places to test |
| `pickup target.com` | Continue where you left off |
| `remember` | Saves current finding to memory |
| `intel target.com` | Pulls CVEs and disclosed reports |
| `chain` | Finds bugs B and C when you found A |
| `scope <asset>` | Checks if domain/URL is in scope |
| `triage` | Quick 2-minute go/no-go check |
| `web3 audit <contract>` | Smart contract security audit |
| `token scan <contract>` | Meme coin/token rug pull scanner |
| `android hunt <app>` | Android APK security testing |
| `ios hunt <app>` | iOS IPA security testing |
| `audit code <repo>` | Source code security audit |

<br>

---

<br>

## AI Agent Roles

11 specialized roles, each for one job:

| Agent | What It Does |
|:---|:---|
| **recon-agent** | Finds all subdomains, live hosts, and URLs |
| **report-writer** | Writes professional, impact-first reports |
| **validator** | Runs the 7-Question Gate on findings |
| **web3-auditor** | Audits smart contracts for 10 vuln classes |
| **chain-builder** | Finds chains of related bugs |
| **autopilot** | Runs the whole hunt loop autonomously |
| **recon-ranker** | Ranks attack surface by priority |
| **token-auditor** | Meme coin / token rug pull analysis |
| **android-auditor** | Android APK reversing + 12 bug classes |
| **ios-auditor** | iOS IPA reversing + 10 bug classes |
| **code-auditor** | Source code audit — 8-phase methodology |

<br>

---

<br>

## Installation

### What You Need First

```bash
# Install Gemini CLI
npm install -g @anthropic-ai/gemini-cli
# Or follow: https://github.com/google-gemini/gemini-cli

# Set your API key
export GEMINI_API_KEY="your-key-here"

# Linux (Ubuntu/Debian)
sudo apt install golang python3 nodejs jq

# macOS
brew install go python3 node jq
```

### Install

```bash
git clone https://github.com/YOUR_USERNAME/gemini-bug-bounty.git
cd gemini-bug-bounty
chmod +x install_tools.sh && ./install_tools.sh   # scanning tools
chmod +x install.sh && ./install.sh               # Gemini context files
```

<br>

---

<br>

## The Rules (Always Active)

```
 1. READ FULL SCOPE FIRST   — only test what the program says you can
 2. ONLY REAL BUGS          — "Can an attacker do this RIGHT NOW?" if no, stop
 3. KILL WEAK FINDINGS FAST — 30-second check saves hours of wasted reporting
 4. NEVER GO OUT OF SCOPE   — one wrong request can get you banned
 5. 5-MINUTE RULE           — no progress after 5 min? move to the next target
 6. VALIDATE BEFORE REPORT  — run validate before you spend 30 min writing
 7. IMPACT FIRST            — start with the bugs that have the worst consequences
```

<br>

---

<br>

## Credits

- **Original project:** [claude-bug-bounty](https://github.com/shuvonsec/claude-bug-bounty) by [shuvonsec](https://shuvonsec.me)
- **Gemini CLI port:** Adapted for Google's Gemini CLI ecosystem

<br>

---

<br>

<div align="center">

**For authorized security testing only.** Only test targets within an approved bug bounty program scope.<br>
Never test systems without explicit written permission. Follow responsible disclosure.

---

<br>

MIT License · **Built by bug hunters, for bug hunters.**

If this helped you find a bug, leave a star ⭐

</div>
