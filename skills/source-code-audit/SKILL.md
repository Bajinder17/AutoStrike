---
name: source-code-audit
description: Complete source code auditing methodology — 8 audit phases covering dangerous function grep (eval, exec, unserialize, raw SQL, SSTI sinks, deserialization gadgets), route-to-controller auth mapping, dependency/SCA scanning (CVE matching), secrets detection (truffleHog, gitleaks), taint analysis patterns, language-specific vuln patterns (Python, JavaScript/TypeScript, Java, Go, PHP, Ruby, Rust, C/C++), diff auditing for new PRs, and automated SAST integration (Semgrep, CodeQL). Includes grep commands, Semgrep rules, and checklists for each language.
---

# SOURCE CODE AUDITING — 8-Phase Methodology

Systematic code review for bug bounty and security assessment.

---

## SETUP

```bash
# SAST tools
pip3 install semgrep                          # Pattern-based SAST
brew install truffleHog gitleaks              # Secret scanning
# CodeQL: https://github.com/github/codeql-cli-binaries

# Helper tools
pip3 install bandit                           # Python SAST
npm install -g eslint @eslint/js              # JS linting
go install github.com/securego/gosec/v2/cmd/gosec@latest  # Go SAST
```

---

## PHASE 1: DANGEROUS FUNCTION GREP (First 15 min)

> Grep the entire codebase for known-dangerous functions. This alone finds 20% of bugs.

### Universal Dangerous Patterns
```bash
# Command injection sinks
grep -rn "exec(\|system(\|popen(\|subprocess\|child_process\|os\.system\|Runtime\.exec" \
  --include="*.py" --include="*.js" --include="*.ts" --include="*.java" --include="*.rb" --include="*.php" --include="*.go"

# Deserialization (RCE vector)
grep -rn "pickle\.loads\|yaml\.load\|unserialize(\|ObjectInputStream\|Marshal\.load\|JSON\.parse.*reviver\|readObject(" \
  --include="*.py" --include="*.php" --include="*.java" --include="*.rb" --include="*.js"

# SQL injection (string concat in queries)
grep -rn "execute(\|\.query(\|\.raw(\|\.exec(" --include="*.py" --include="*.js" --include="*.java" --include="*.rb" | \
  grep -E "\+.*\"|f\"|%s|format\("

# SSTI sinks
grep -rn "render_template_string\|Template(\|Jinja2\|eval(\|ERB\.new" \
  --include="*.py" --include="*.rb" --include="*.java"

# Path traversal
grep -rn "open(\|readFile\|createReadStream\|fs\.\|File\.new\|os\.path\.join" \
  --include="*.py" --include="*.js" --include="*.ts" --include="*.rb" | grep -v "node_modules"

# Hardcoded secrets (immediate check)
grep -rn "password\s*=\s*[\"']\|api_key\s*=\s*[\"']\|secret\s*=\s*[\"']\|AKIA[0-9A-Z]\{16\}" \
  --include="*.py" --include="*.js" --include="*.java" --include="*.go" --include="*.env" | \
  grep -v "test\|example\|placeholder\|TODO"
```

---

## PHASE 2: ROUTE → CONTROLLER AUTH MAPPING (20 min)

> Map every route to its controller. Find the one without auth middleware.

### Express.js / Node.js
```bash
# Find all route definitions
grep -rn "router\.\(get\|post\|put\|delete\|patch\)\|app\.\(get\|post\|put\|delete\)" \
  --include="*.js" --include="*.ts" | head -100

# Find routes WITHOUT auth middleware
# Pattern: router.get('/path', handler)  ← missing middleware
# vs:      router.get('/path', authMiddleware, handler)  ← has auth
grep -rn "router\.\(get\|post\|put\|delete\)" --include="*.js" --include="*.ts" | \
  grep -v "auth\|authenticate\|authorize\|isLoggedIn\|requireAuth\|protect\|verify"
```

### Django / Flask (Python)
```bash
# Django views without @login_required
grep -rn "def \w\+(.*request" --include="*.py" -l | while read f; do
  grep -L "login_required\|permission_required\|IsAuthenticated" "$f"
done

# Flask routes without auth decorator
grep -rn "@app\.route\|@bp\.route\|@blueprint\.route" --include="*.py" -A2 | \
  grep -v "login_required\|auth_required\|jwt_required"
```

### Spring Boot (Java)
```bash
# Controllers without @PreAuthorize or @Secured
grep -rn "@RequestMapping\|@GetMapping\|@PostMapping\|@PutMapping\|@DeleteMapping" \
  --include="*.java" -A1 | grep -v "PreAuthorize\|Secured\|RolesAllowed"

# SecurityConfig — check antMatchers for permitAll
grep -rn "permitAll\|anonymous\|antMatchers" --include="*.java"
```

### Rails (Ruby)
```bash
# Controllers missing before_action :authenticate
grep -rn "class.*Controller" --include="*.rb" -A5 | \
  grep -v "before_action.*auth\|before_filter.*auth"

# Check routes for unprotected resources
grep -rn "resources\|get\|post\|put\|delete" config/routes.rb
```

### Go (Gin/Echo/Fiber)
```bash
# Routes without auth middleware
grep -rn "\.GET(\|\.POST(\|\.PUT(\|\.DELETE(" --include="*.go" | \
  grep -v "Auth\|JWT\|middleware\|Protected"
```

---

## PHASE 3: DEPENDENCY / SCA SCANNING (10 min)

```bash
# Node.js
npm audit --json 2>/dev/null | jq '.vulnerabilities | to_entries[] | select(.value.severity == "critical" or .value.severity == "high")'

# Python
pip-audit --format=json 2>/dev/null | jq '.[] | select(.fix_versions != [])'
safety check -r requirements.txt --json 2>/dev/null

# Java (Maven)
mvn dependency-check:check 2>/dev/null

# Go
govulncheck ./... 2>/dev/null

# Rust
cargo audit 2>/dev/null

# Ruby
bundle audit check 2>/dev/null

# Universal: Semgrep supply chain
semgrep --config=p/supply-chain .
```

---

## PHASE 4: SECRET SCANNING (5 min)

```bash
# truffleHog (git history)
trufflehog git file://. --json | jq '.Raw'

# gitleaks
gitleaks detect -s . --report-format json -r gitleaks_report.json
cat gitleaks_report.json | jq '.[].Description'

# Manual high-value patterns
grep -rn "-----BEGIN\|-----BEGIN RSA\|-----BEGIN PRIVATE" .
grep -rn "ghp_\|gho_\|glpat-\|sk-\|pk_live_\|sk_live_\|xoxb-\|xoxp-" .
grep -rn "AKIA[0-9A-Z]\{16\}" .
grep -rn "mongodb://\|postgres://\|mysql://\|redis://" . | grep -v "localhost\|127\.0\.0\.1\|example"
```

---

## PHASE 5: LANGUAGE-SPECIFIC PATTERNS

### Python
```bash
# Pickle deserialization (RCE)
grep -rn "pickle\.loads\|pickle\.load\|cPickle" --include="*.py"

# Unsafe YAML (RCE via !!python/object)
grep -rn "yaml\.load\b" --include="*.py" | grep -v "yaml\.safe_load\|Loader=SafeLoader"

# eval/exec on user input
grep -rn "eval(\|exec(\|compile(" --include="*.py" | grep -v "test\|#"

# Django ORM raw queries
grep -rn "\.raw(\|\.extra(\|RawSQL\|connection\.cursor" --include="*.py"

# SSTI
grep -rn "render_template_string\|Template(\|Markup(" --include="*.py"

# Mass assignment (Django)
grep -rn "exclude\s*=\s*\[\]\|fields\s*=\s*'__all__'" --include="*.py"
```

### JavaScript / TypeScript
```bash
# Prototype pollution
grep -rn "merge(\|extend(\|assign(\|defaultsDeep\|\.set(" --include="*.js" --include="*.ts" | \
  grep -v "node_modules"

# DOM XSS sinks
grep -rn "innerHTML\|outerHTML\|document\.write\|\.html(\|v-html\|dangerouslySetInnerHTML" \
  --include="*.js" --include="*.ts" --include="*.jsx" --include="*.tsx" --include="*.vue" | \
  grep -v "node_modules"

# eval and friends
grep -rn "eval(\|Function(\|setTimeout.*string\|setInterval.*string" \
  --include="*.js" --include="*.ts" | grep -v "node_modules"

# NoSQL injection
grep -rn "\$where\|\$gt\|\$ne\|\$regex\|\.find({" --include="*.js" --include="*.ts"

# Path traversal in Express
grep -rn "req\.params\|req\.query\|req\.body" --include="*.js" --include="*.ts" | \
  grep -E "path\.\|fs\.\|readFile\|createReadStream"
```

### Java
```bash
# Deserialization (RCE via gadget chains)
grep -rn "ObjectInputStream\|readObject\|XMLDecoder\|XStream\|fromXML" --include="*.java"

# SQL injection
grep -rn "createQuery\|createNativeQuery\|Statement\|PreparedStatement" --include="*.java" | \
  grep -E "\+.*\"|\"|concat"

# SSRF
grep -rn "URL(\|HttpURLConnection\|HttpClient\|RestTemplate\|WebClient" --include="*.java" | \
  grep -v "test\|mock"

# XXE
grep -rn "DocumentBuilder\|SAXParser\|XMLReader\|TransformerFactory" --include="*.java"
# Check for: setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)

# Spring Actuators exposed
grep -rn "management\.endpoints\|actuator" --include="*.properties" --include="*.yml" --include="*.yaml"
```

### Go
```bash
# Command injection
grep -rn "exec\.Command\|os/exec" --include="*.go" | grep -v "_test\.go"

# SQL injection
grep -rn "fmt\.Sprintf.*SELECT\|fmt\.Sprintf.*INSERT\|fmt\.Sprintf.*UPDATE\|db\.Query.*\+" \
  --include="*.go"

# SSRF
grep -rn "http\.Get\|http\.Post\|http\.NewRequest\|url\.Parse" --include="*.go"

# Path traversal
grep -rn "os\.Open\|ioutil\.ReadFile\|filepath\.Join" --include="*.go" | \
  grep -E "r\.URL\|r\.Form\|params\["
```

### PHP
```bash
# RCE
grep -rn "eval(\|exec(\|system(\|passthru(\|shell_exec(\|popen(\|proc_open(" --include="*.php"

# Deserialization
grep -rn "unserialize(\|__wakeup\|__destruct" --include="*.php"

# SQL injection
grep -rn "mysql_query\|mysqli_query\|->query(" --include="*.php" | grep "\$"

# File inclusion
grep -rn "include(\|require(\|include_once(\|require_once(" --include="*.php" | grep "\$"

# SSRF
grep -rn "file_get_contents(\|curl_exec(\|fopen(" --include="*.php" | grep "\$"
```

### C/C++
```bash
# Buffer overflow
grep -rn "strcpy\|strcat\|sprintf\|gets\|scanf.*%s" --include="*.c" --include="*.cpp" --include="*.h"

# Format string
grep -rn "printf(\|fprintf(\|sprintf(" --include="*.c" --include="*.cpp" | grep -v '\".*%'

# Integer overflow
grep -rn "malloc(\|calloc(\|realloc(" --include="*.c" --include="*.cpp" | grep -E "\*|\+"

# Use-after-free patterns
grep -rn "free(\|delete " --include="*.c" --include="*.cpp" -A5 | grep -E "->|\.|\["
```

---

## PHASE 6: SEMGREP RULES (Automated SAST)

```bash
# Run all security rules
semgrep --config=auto .

# High-signal rule packs
semgrep --config=p/security-audit .
semgrep --config=p/owasp-top-ten .
semgrep --config=p/secrets .

# Language-specific
semgrep --config=p/python .
semgrep --config=p/javascript .
semgrep --config=p/java .
semgrep --config=p/golang .

# Custom rules for highest-value bugs
cat > /tmp/custom_rules.yml << 'EOF'
rules:
  - id: unauth-route
    patterns:
      - pattern: router.$METHOD($PATH, $HANDLER)
      - pattern-not: router.$METHOD($PATH, auth, $HANDLER)
      - pattern-not: router.$METHOD($PATH, authenticate, $HANDLER)
    message: "Route without auth middleware"
    severity: WARNING
    languages: [javascript, typescript]

  - id: raw-sql
    pattern: |
      $DB.query("..." + $INPUT)
    message: "SQL injection via string concatenation"
    severity: ERROR
    languages: [javascript, typescript]
EOF
semgrep --config=/tmp/custom_rules.yml .
```

---

## PHASE 7: DIFF / PR AUDITING

> New code = least reviewed = highest bug density. Focus PRs from last 30 days.

```bash
# Last 30 days of changes
git log --since="30 days ago" --oneline --stat | head -100

# Show files changed in recent commits
git diff HEAD~50 --name-only | sort | uniq -c | sort -rn | head -20

# Diff audit for auth changes
git log --since="30 days ago" -p -- "*.py" "*.js" "*.java" | \
  grep -E "^\+.*auth\|^\+.*permission\|^\+.*role\|^-.*auth\|^-.*permission"

# New routes added recently
git log --since="30 days ago" -p | grep -E "^\+.*(route|endpoint|@app\.|@Get|@Post)"

# Security-sensitive file changes
git log --since="30 days ago" --all -- "*auth*" "*security*" "*permission*" "*config*" "*secret*"
```

---

## PHASE 8: TAINT ANALYSIS PATTERNS

> Track user input from source → sink. If no sanitization in between → vulnerability.

### Source → Sink Mapping

| Language | Sources | Sinks |
|---|---|---|
| **Python** | `request.args`, `request.form`, `request.json`, `sys.argv` | `eval()`, `exec()`, `os.system()`, `subprocess.run()`, `cursor.execute()`, `render_template_string()` |
| **JavaScript** | `req.params`, `req.query`, `req.body`, `location.hash` | `eval()`, `innerHTML`, `document.write()`, `child_process.exec()`, `db.query()` |
| **Java** | `request.getParameter()`, `@RequestBody`, `@PathVariable` | `Runtime.exec()`, `Statement.execute()`, `ProcessBuilder`, `JNDI lookup` |
| **Go** | `r.URL.Query()`, `r.FormValue()`, `r.Body` | `exec.Command()`, `db.Query()`, `template.HTML()`, `os.Open()` |
| **PHP** | `$_GET`, `$_POST`, `$_REQUEST`, `$_COOKIE` | `eval()`, `system()`, `mysql_query()`, `include()`, `unserialize()` |

### Manual Taint Trace
```
1. Identify user input entry point (source)
2. Follow variable through function calls
3. Check for sanitization/validation at each step
4. If variable reaches dangerous function (sink) unsanitized → BUG
```

---

## AUDIT OUTPUT FORMAT

```markdown
# Source Code Audit: [repo-name]

## Finding [N]: [Bug Class] in [file:line]

**Severity:** Critical / High / Medium
**CWE:** CWE-XXX
**CVSS:** X.X

### Vulnerable Code
[exact snippet with file path and line numbers]

### Root Cause
[one sentence — why this is exploitable]

### Exploitation
[curl command or PoC script]

### Fix
[exact code diff]
```

---

## AUDIT CHECKLIST

```
[ ] Phase 1: Dangerous function grep complete
[ ] Phase 2: All routes mapped, auth coverage verified
[ ] Phase 3: Dependency scan — critical CVEs checked
[ ] Phase 4: Secret scan — git history included
[ ] Phase 5: Language-specific patterns checked
[ ] Phase 6: Semgrep run with security-audit + owasp packs
[ ] Phase 7: Recent PRs/diffs reviewed for auth changes
[ ] Phase 8: Taint analysis on critical data flows
```
