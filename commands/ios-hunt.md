---
description: Hunt iOS app for vulnerabilities — 18 bug classes. Reverse IPA, grep secrets, test URL schemes, exploit WKWebView, check ATS, dump Keychain, bypass SSL pinning, test biometric bypass, Universal Links, extensions, custom keyboards, IPC, notifications, local auth. Asset types — App Store, TestFlight, .ipa. Usage: "ios hunt com.target.app" or "ios hunt target.ipa"
---

# ios hunt

Active vulnerability hunting on an iOS application.

## What This Does

1. Extracts and reverses the IPA (class-dump + strings)
2. Runs automated secret grep (API keys, certificates, Firebase)
3. Parses Info.plist for URL schemes, ATS exceptions, permissions
4. Tests each attack surface in order of ROI
5. Documents findings with exact commands

## Usage

```
ios hunt com.target.app                  # bundle ID (extract from device)
ios hunt target.ipa                      # local IPA file
ios hunt target.ipa --dynamic            # include Frida/objection runtime tests
ios hunt target.ipa --focus schemes      # focus on URL scheme attacks
```

## Phase 1: IPA Extraction & Reversing (5 min)

```bash
# Extract IPA
unzip target.ipa -d target_extracted/

# Binary analysis
class-dump target_extracted/Payload/App.app/App > headers.h
strings target_extracted/Payload/App.app/App > strings.txt

# Info.plist
plutil -p target_extracted/Payload/App.app/Info.plist
```

## Phase 2: Quick Wins — Secrets & Config (10 min)

```bash
# Hardcoded secrets
grep -iE "api_key|secret|password|token|bearer|AKIA|AIza" strings.txt
find target_extracted/ -name "*.plist" -exec plutil -p {} \; | grep -iE "key|secret|token"

# ATS exceptions (HTTP allowed?)
plutil -p target_extracted/Payload/App.app/Info.plist | grep -A10 "NSAppTransportSecurity"

# Embedded certs/keys
find target_extracted/ -name "*.p12" -o -name "*.pem" -o -name "*.cer"
```

## Phase 3: URL Scheme Testing (10 min)

```bash
# Extract schemes
plutil -p target_extracted/Payload/App.app/Info.plist | grep -A5 "CFBundleURLSchemes"

# Verify Universal Links
curl -s "https://target.com/.well-known/apple-app-site-association" | jq .

# Fuzz schemes
for payload in "https://evil.com" "javascript:alert(1)" "file:///etc/passwd"; do
  xcrun simctl openurl booted "targetscheme://callback?url=$payload"
done
```

## Phase 4: Dynamic Analysis (if --dynamic)

```bash
# objection runtime analysis
objection -g com.target.app explore
ios keychain dump
ios nsuserdefaults get
ios cookies get
ios pasteboard monitor
android sslpinning disable  # yes, same command in objection

# Frida jailbreak + SSL bypass
frida -U -f com.target.app -l bypass.js --no-pause
```

## Priority Order

1. **Hardcoded secrets with proven access** (Critical)
2. **URL scheme hijack → OAuth token theft** (Critical)
3. **Biometric auth bypass (client-only, no server validation)** (Critical)
4. **ATS disabled → MitM all traffic** (High)
5. **WKWebView JS injection** (High)
6. **Keychain weak access control (kSecAttrAccessibleAlways)** (High)
7. **Universal Links misconfiguration (AASA)** (High)
8. **Local Authentication framework bypass** (High)
9. **IPC abuse (XPC, App Group token access)** (High)
10. **NSUserDefaults plaintext secrets** (Medium)
11. **App Extension data sharing (shared containers)** (Medium–High)
12. **Push notification data on lock screen** (Medium)
13. **Custom keyboard data leakage** (Medium–High)
14. **Clipboard sensitive data** (Medium)
15. **Third-party SDK with known CVE** (Medium–Critical)
16. **Third-party SDK PII exfiltration** (Medium)
17. **Background screenshot leakage** (Low–Medium)
18. **Binary protections missing** (Low)

## Stop Signals

- Binary is heavily stripped + no jailbroken device for dynamic
- No URL schemes, no WebViews, no ATS exceptions
- All secrets are test/example values
- App is a thin wrapper around a web app (test web surface instead)
- AASA properly configured on correct domain
- Biometric auth is server-validated with Secure Enclave
- Custom keyboards blocked via shouldAllowExtensionPointIdentifier
- No app extensions or shared data containers
