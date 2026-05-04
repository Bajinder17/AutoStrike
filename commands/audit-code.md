---
description: Audit source code for security vulnerabilities — grep dangerous functions, map route auth coverage, scan dependencies, detect secrets, run Semgrep/CodeQL, audit recent diffs. Usage: "audit code ./path/to/repo" or "audit code https://github.com/org/repo"
---

# audit code

Systematic source code security audit.

## What This Does

1. Clones repo (if URL) or reads local path
2. Detects language/framework stack
3. Runs 8-phase audit methodology
4. Outputs findings with severity, CWE, and fix recommendations

## Usage

```
audit code ./path/to/repo                         # local directory
audit code https://github.com/org/repo            # clone from GitHub
audit code ./repo --focus auth                    # focus on auth/access control
audit code ./repo --focus injection               # focus on injection bugs
audit code ./repo --focus secrets                 # secrets + credentials only
audit code ./repo --diff-only                     # only audit last 30 days of changes
audit code ./repo --language python               # force language detection
```

## Phase 1: Language Detection & Dangerous Function Grep (15 min)

```bash
# Auto-detect stack
find . -name "*.py" -o -name "*.js" -o -name "*.java" -o -name "*.go" -o -name "*.php" -o -name "*.rb" | \
  head -1 | xargs file

# Run universal dangerous function scan
# (exact commands from skills/source-code-audit/SKILL.md Phase 1)
```

## Phase 2: Route → Auth Mapping (20 min)

```
For EVERY route definition found:
  1. Does it have auth middleware/decorator?
  2. Does auth check cover ALL HTTP methods?
  3. Is there a sibling route without auth?
```

## Phase 3: Dependency Scan (10 min)

```bash
# Detect package manager and run appropriate audit
[ -f package.json ] && npm audit --json
[ -f requirements.txt ] && pip-audit -r requirements.txt
[ -f go.sum ] && govulncheck ./...
[ -f Gemfile.lock ] && bundle audit check
[ -f pom.xml ] && mvn dependency-check:check
```

## Phase 4: Secret Scan (5 min)

```bash
trufflehog git file://. --json 2>/dev/null | head -20
gitleaks detect -s . --report-format json 2>/dev/null
```

## Phase 5: Semgrep SAST (10 min)

```bash
semgrep --config=auto --config=p/security-audit --config=p/owasp-top-ten .
```

## Phase 6: Diff Audit (if --diff-only or always for recent changes)

```bash
git log --since="30 days ago" -p -- "*.py" "*.js" "*.java" "*.go" | \
  grep -E "^\+.*(eval|exec|query|raw|system|unserialize|innerHTML)"
```

## Output Format

For each finding, output:
```
FINDING: [Bug Class] in [file:line]
SEVERITY: Critical / High / Medium
CWE: CWE-XXX
ROOT CAUSE: [one sentence]
CODE: [exact vulnerable snippet]
FIX: [exact code change]
EXPLOITABLE: YES/NO — [why]
```

## Stop Signals

- Entire codebase is auto-generated / scaffolding
- All routes behind enterprise auth gateway (Okta, Auth0)
- Zero dangerous functions found + clean Semgrep scan
- Repository is archived with no recent activity
