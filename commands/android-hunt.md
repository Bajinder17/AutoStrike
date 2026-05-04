---
description: Hunt Android app for vulnerabilities — 20 bug classes. Decompile APK, grep secrets, test deep links, exploit WebViews, check exported components, bypass cert pinning, test PendingIntents, fragment injection, StrandHogg, network config, SDK vulns, clipboard, notifications. Asset types — Play Store, .apk. Usage: "android hunt com.target.app" or "android hunt target.apk"
---

# android hunt

Active vulnerability hunting on an Android application.

## What This Does

1. Acquires and decompiles the APK (apktool + jadx)
2. Runs automated secret grep (API keys, tokens, Firebase, AWS)
3. Parses AndroidManifest.xml for exported components and deep links
4. Tests each attack surface in order of ROI
5. Documents findings with exact ADB/curl commands

## Usage

```
android hunt com.target.app              # package name (pulls from device)
android hunt target.apk                  # local APK file
android hunt target.apk --dynamic        # include Frida/objection runtime tests
android hunt target.apk --focus webview   # focus on one bug class
```

## Phase 1: APK Acquisition & Reversing (5 min)

```bash
# From device
adb shell pm path com.target.app
adb pull /data/app/com.target.app-1/base.apk target.apk

# Decompile
apktool d target.apk -o target_smali/
jadx -d target_java/ target.apk
```

## Phase 2: Quick Wins — Secrets & Config (10 min)

```bash
# Hardcoded secrets
grep -rn "api_key\|secret\|password\|token\|AKIA\|AIza" target_java/ \
  --include="*.java" --include="*.xml" | grep -v "R.java\|BuildConfig"

# Firebase open database
grep -rn "firebaseio.com" target_java/
# → curl "https://FOUND.firebaseio.com/.json"

# AndroidManifest analysis
cat target_smali/AndroidManifest.xml | grep -E "exported|debuggable|allowBackup|scheme|permission"
```

## Phase 3: Deep Link Testing (10 min)

```bash
# Extract all schemes
grep -A5 "CFBundleURLSchemes\|android:scheme" target_smali/AndroidManifest.xml

# Fuzz each scheme
for payload in "https://evil.com" "javascript:alert(1)" "file:///etc/passwd"; do
  adb shell am start -a android.intent.action.VIEW -d "targetscheme://callback?url=$payload"
done
```

## Phase 4: WebView & Component Testing (15 min)

```bash
# WebView misconfigs
grep -rn "addJavascriptInterface\|setAllowUniversalAccessFromFileURLs\|loadUrl" target_java/

# Exported component abuse
grep -B2 -A10 "exported=\"true\"" target_smali/AndroidManifest.xml
# Launch each exported activity/service
```

## Phase 5: Dynamic Analysis (if --dynamic)

```bash
# Bypass cert pinning
objection -g com.target.app explore -c "android sslpinning disable"

# Monitor runtime
adb logcat -d | grep -iE "token|password|session|secret"

# Intercept traffic via Burp proxy
# adb shell settings put global http_proxy BURP_IP:8080
```

## Priority Order

1. **Hardcoded secrets with proven access** (Critical)
2. **Deep link → OAuth token theft** (Critical)
3. **WebView RCE via JSInterface** (Critical)
4. **StrandHogg / task hijacking** (Critical)
5. **Exported content provider → SQLi/traversal** (High)
6. **Intent redirection/hijacking** (High)
7. **PendingIntent hijacking (implicit intent)** (High)
8. **Fragment injection on PreferenceActivity** (High)
9. **Insecure data storage** (Medium–High)
10. **Network security config — cleartext allowed** (High)
11. **Clipboard data leakage (auth tokens)** (Medium–High)
12. **Notification data exposure on lock screen** (Medium)
13. **Third-party SDK with known CVE** (Medium–Critical)
14. **Backup exploitation** (Medium)
15. **Logging sensitive data** (Medium)
16. **Runtime permission abuse** (Medium)
17. **Tapjacking on payment dialogs** (Medium)
18. **Broadcast receiver abuse** (Medium)

## Stop Signals

- APK is heavily obfuscated + no dynamic testing available
- All components are unexported with proper permissions
- No API keys, no deep links, no WebViews
- Certificate pinning cannot be bypassed + no rooted device
- PendingIntents use FLAG_IMMUTABLE + explicit intents
- Network security config properly restricts cleartext
- No fragment injection surface (isValidFragment overridden)
