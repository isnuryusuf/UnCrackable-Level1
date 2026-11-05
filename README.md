# UnCrackable-Level1 APK — Root Detection Bypass (CRACKED)

> **Status:** ✅ Successfully cracked and modified APK deployed to emulator.
> **Date:** 2026-11-05
> **Target:** `UnCrackable-Level1.apk` (OWASP Mobile Security Testing Guide)

---

## Quick Summary

**ALL security checks in the UnCrackable-Level1 APK have been bypassed.** Both root detection and secret string verification have been disabled by modifying Smali bytecode. The modified APK (`final_app.apk`) is signed, aligned, and installed on the connected ADB device.

### Key Changes

| # | Method | File | Original Behavior | Modified Behavior |
|---|--------|------|------------------|-------------------|
| 1 | `c.a()` | [`sg/vantagepoint/a/c.smali`](app_decompiled/smali/sg/vantagepoint/a/c.smali:6) | Scans PATH for `su` binary | Always returns `false` |
| 2 | `c.b()` | [`sg/vantagepoint/a/c.smali`](app_decompiled/smali/sg/vantagepoint/a/c.smali:12) | Checks `Build.TAGS` for "test-keys" | Always returns `false` |
| 3 | `c.c()` | [`sg/vantagepoint/a/c.smali`](app_decompiled/smali/sg/vantagepoint/a/c.smali:18) | Checks 7 known root app file paths | Always returns `false` |
| 4 | `a.a()` | [`sg/vantagepoint/uncrackable1/a.smali`](app_decompiled/smali/sg/vantagepoint/uncrackable1/a.smali:6) | Verifies AES-decrypted secret string | Always returns `true` |

**Total lines removed:** 146 lines of security logic
**Total lines added:** 16 lines (simple return statements)

---

## Step-by-Step Instructions

### Prerequisites

- Windows 10+
- Java JDK 25+ installed
- ADB installed and accessible

### Tools Used (All Local in This Project)

| Tool | Version | Location |
|------|---------|----------|
| Java (JDK) | 25.0.5 (Temurin) | System JDK |
| apktool | 2.6.1 | [`build-tools/apktool.jar`](build-tools/apktool.jar) |
| JADX | 1.4.7 | [`bin/jadx.bat`](bin/jadx.bat) |
| zipalign | 37.0.1 | [`build-tools/android-13/zipalign.exe`](build-tools/android-13/zipalign.exe) |
| apksigner | 37.0.1 | [`build-tools/android-13/apksigner.bat`](build-tools/android-13/apksigner.bat) |
| keytool | 25.0.5 | Bundled with JDK |

A convenience wrapper [`apktool.bat`](apktool.bat) has been created for easy access to apktool.

---

### Step 1: Environment Setup

All required tools are already present in the workspace under `build-tools/` and `lib/`.

```bat
REM Verify Java
java -version

REM Verify apktool
java -jar build-tools\apktool.jar --version

REM Verify JADX
bin\jadx.bat --version
```

---

### Step 2: Decompile APK

```bat
java -jar build-tools\apktool.jar d UnCrackable-Level1.apk -o app_decompiled -f --frame-path .\frame_cache
```

This produces the `app_decompiled/` directory containing:
- `smali/` — Smali bytecode (decompiled from DEX)
- `res/` — Android resources
- `AndroidManifest.xml` — App manifest
- `resources.arsc` — Compiled resources

---

### Step 3: Inspect Java Source with JADX

```bat
bin\jadx.bat UnCrackable-Level1.apk -d app_java -r
```

This decompiles the APK into human-readable Java code under `app_java/`.

---

### Step 4: Locate Root Detection Code

#### Detection Class: `sg.vantagepoint.a.c`

| Method | File | Function |
|--------|------|----------|
| `a()` | [`c.java:7-14`](app_java/sources/sg/vantagepoint/a/c.java:7) | Scans `$PATH` directories for a `su` binary |
| `b()` | [`c.java:16-19`](app_java/sources/sg/vantagepoint/a/c.java:16) | Checks if `Build.TAGS` contains `"test-keys"` (debug/test build indicator) |
| `c()` | [`c.java:21-28`](app_java/sources/sg/vantagepoint/a/c.java:21) | Checks for 7 known root app files (Superuser.apk, daemonsu, etc.) |

#### Caller: `MainActivity.onCreate()`

In [`MainActivity.java:30`](app_java/sources/sg/vantagepoint/uncrackable1/MainActivity.java:30):

```java
if (c.a() || c.b() || c.c()) {
    a("Root detected!");  // Shows alert dialog and exits the app
}
```

---

### Step 5: Modify Smali Code

**File:** [`app_decompiled/smali/sg/vantagepoint/a/c.smali`](app_decompiled/smali/sg/vantagepoint/a/c.smali)

#### Method `a()` — PATH scan for `su`

**Before (lines 6–55, 49 lines):**
```smali
.method public static a()Z
    .locals 7
    const-string v0, "PATH"
    invoke-static {v0}, Ljava/lang/System;->getenv(Ljava/lang/String;)Ljava/lang/String;
    move-result-object v0
    const-string v1, ":"
    invoke-virtual {v0, v1}, Ljava/lang/String;->split(Ljava/lang/String;)[Ljava/lang/String;
    move-result-object v0
    array-length v1, v0
    const/4 v2, 0x0
    const/4 v3, 0x0
    :goto_0
    if-ge v3, v1, :cond_1
    aget-object v4, v0, v3
    new-instance v5, Ljava/io/File;
    const-string v6, "su"
    invoke-direct {v5, v4, v6}, Ljava/io/File;-><init>(Ljava/lang/String;Ljava/lang/String;)V
    invoke-virtual {v5}, Ljava/io/File;->exists()Z
    move-result v4
    if-eqz v4, :cond_0
    const/4 v0, 0x1
    return v0
    :cond_0
    add-int/lit8 v3, v3, 0x1
    goto :goto_0
    :cond_1
    return v2
.end method
```

**After (lines 6–10, 4 lines):**
```smali
.method public static a()Z
    .locals 1
    const/4 v0, 0x0
    return v0
.end method
```

#### Method `b()` — Build.TAGS test-keys check

**Before (lines 57–80, 23 lines):**
```smali
.method public static b()Z
    .locals 2
    sget-object v0, Landroid/os/Build;->TAGS:Ljava/lang/String;
    if-eqz v0, :cond_0
    const-string v1, "test-keys"
    invoke-virtual {v0, v1}, Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z
    move-result v0
    if-eqz v0, :cond_0
    const/4 v0, 0x1
    return v0
    :cond_0
    const/4 v0, 0x0
    return v0
.end method
```

**After (lines 12–16, 4 lines):**
```smali
.method public static b()Z
    .locals 1
    const/4 v0, 0x0
    return v0
.end method
```

#### Method `c()` — Known root file paths check

**Before (lines 82–135, 53 lines):**
```smali
.method public static c()Z
    .locals 7
    const-string v0, "/system/app/Superuser.apk"
    const-string v1, "/system/xbin/daemonsu"
    const-string v2, "/system/etc/init.d/99SuperSUDaemon"
    const-string v3, "/system/bin/.ext/.su"
    const-string v4, "/system/etc/.has_su_daemon"
    const-string v5, "/system/etc/.installed_su_daemon"
    const-string v6, "/dev/com.koushikdutta.superuser.daemon/"
    filled-new-array/range {v0 .. v6}, [Ljava/lang/String;
    move-result-object v0
    array-length v1, v0
    const/4 v2, 0x0
    const/4 v3, 0x0
    :goto_0
    if-ge v3, v1, :cond_1
    aget-object v4, v0, v3
    new-instance v5, Ljava/io/File;
    invoke-direct {v5, v4}, Ljava/io/File;-><init>(Ljava/lang/String;)V
    invoke-virtual {v5}, Ljava/io/File;->exists()Z
    move-result v4
    if-eqz v4, :cond_0
    const/4 v0, 0x1
    return v0
    :cond_0
    add-int/lit8 v3, v3, 0x1
    goto :goto_0
    :cond_1
    return v2
.end method
```

**After (lines 18–22, 4 lines):**
```smali
.method public static c()Z
    .locals 1
    const/4 v0, 0x0
    return v0
.end method
```

---

### Step 5b: Bypass Secret String Verification ("Enter the Secret String" Form)

The app has a second security check: an input field that requires entering the correct secret string to pass verification. This check uses AES-256 decryption with a hardcoded key.

#### Original Logic

In [`sg.vantagepoint.uncrackable1.a`](app_java/sources/sg/vantagepoint/uncrackable1/a.java), the `a(String)` method:

1. Takes user input from the "Enter the Secret String" text field
2. Decrypts an encrypted blob using AES with a hex-encoded key (`8d127684cbc37c17616d806cf50473cc`)
3. Compares the decrypted bytes (Base64: `5UJiFctbmgbDoLXmpL12mkno8HT4Lv8dlat8FxR2GOc=`) with user input
4. Returns `true` only if they match exactly

The caller in [`MainActivity.verify()`](app_java/sources/sg/vantagepoint/uncrackable1/MainActivity.java:44):
```java
if (a.a(obj)) {
    create.setTitle("Success!");       // Correct secret
    str = "This is the correct secret.";
} else {
    create.setTitle("Nope...");       // Wrong secret
    str = "That's not it. Try again.";
}
```

#### Smali Location

File: [`app_decompiled/smali/sg/vantagepoint/uncrackable1/a.smali`](app_decompiled/smali/sg/vantagepoint/uncrackable1/a.smali)

**Before (lines 6–71, 65 lines):**
```smali
.method public static a(Ljava/lang/String;)Z
    .locals 5

    const-string v0, "8d127684cbc37c17616d806cf50473cc"

    const-string v1, "5UJiFctbmgbDoLXmpL12mkno8HT4Lv8dlat8FxR2GOc="

    const/4 v2, 0x0

    invoke-static {v1, v2}, Landroid/util/Base64;->decode(Ljava/lang/String;I)[B

    move-result-object v1

    new-array v2, v2, [B

    :try_start_0
    invoke-static {v0}, Lsg/vantagepoint/uncrackable1/a;->b(Ljava/lang/String;)[B

    move-result-object v0

    invoke-static {v0, v1}, Lsg/vantagepoint/a/a;->a([B[B)[B

    move-result-object v0
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    goto :goto_0

    :catch_0
    move-exception v0

    const-string v1, "CodeCheck"

    new-instance v3, Ljava/lang/StringBuilder;

    invoke-direct {v3}, Ljava/lang/StringBuilder;-><init>()V

    const-string v4, "AES error:"

    invoke-virtual {v3, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/Exception;->getMessage()Ljava/lang/String;

    move-result-object v0

    invoke-virtual {v3, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    invoke-static {v1, v0}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    move-object v0, v2

    :goto_0
    new-instance v1, Ljava/lang/String;

    invoke-direct {v1, v0}, Ljava/lang/String;-><init>([B)V

    invoke-virtual {p0, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result p0

    return p0
.end method
```

**After (lines 6–10, 4 lines):**
```smali
.method public static a(Ljava/lang/String;)Z
    .locals 1
    const/4 v0, 0x1
    return v0
.end method
```

This change makes the verification always succeed — any input (or no input) will display "Success! This is the correct secret."

---

### Step 6: Rebuild APK

```bat
java -jar build-tools\apktool.jar b app_decompiled -o modified_app.apk
```

---

### Step 7: Create Keystore, Align & Sign

#### 7a. Create Release Keystore

```bat
keytool -genkey -v -keystore my-release-key.jks ^
    -keyalg RSA -keysize 2048 -validity 10000 -alias mykey ^
    -keypass password -storepass password ^
    -dname "CN=UnCrackable, OU=Testing, O=Security, L=City, ST=State, C=US"
```

**Keystore details:**
| Parameter | Value |
|-----------|-------|
| File | `my-release-key.jks` |
| Alias | `mykey` |
| Store Password | `password` |
| Key Password | `password` |
| Algorithm | RSA 2048-bit |
| Validity | 10,000 days |

#### 7b. Zipalign

```bat
build-tools\android-13\zipalign.exe -v -p 4 modified_app.apk final_app.apk
```

#### 7c. Sign with apksigner

```bat
build-tools\android-13\apksigner.bat sign ^
    --ks my-release-key.jks ^
    --ks-pass pass:password ^
    --ks-key-alias mykey ^
    --key-pass pass:password ^
    --v4-signing-enabled false ^
    final_app.apk
```

#### 7d. Verify Signature

```bat
build-tools\android-13\apksigner.bat verify --verbose final_app.apk
```

Expected output:
```
Verified using v1 scheme (JAR signing): true
Verified using v2 scheme (APK Signature Scheme v2): true
Verified using v3 scheme (APK Signature Scheme v3): true
Number of signers: 1
```

---

### Step 8: Install on ADB Device

```bat
REM Uninstall previous version (if exists)
adb uninstall owasp.mstg.uncrackable1

REM Install modified APK
adb install final_app.apk
```

Result: `Success`

---

## Final Artifacts

| File | Size | Description |
|------|------|-------------|
| [`final_app.apk`](final_app.apk) | ~66 KB | **Signed, aligned, fully cracked APK** (delivery artifact — root + secret bypassed) |
| [`modified_app.apk`](modified_app.apk) | ~66 KB | Intermediate unsigned APK (pre-zipalign) |
| [`my-release-key.jks`](my-release-key.jks) | ~2 KB | Release keystore (password: `password`) |
| [`app_decompiled/`](app_decompiled/) | — | Full decompiled source (Smali + resources) |
| [`app_java/`](app_java/) | — | JADX decompiled Java source (reference only) |

---

## Verification Checklist

- [x] APK decompiles with apktool without errors
- [x] JADX produces readable Java source
- [x] All 3 root detection methods (`c.a`, `c.b`, `c.c`) return `false`
- [x] Secret verification method (`a.a`) always returns `true` — any input passes
- [x] APK rebuilds successfully
- [x] APK is zipaligned (4-byte alignment)
- [x] APK is signed with v1/v2/v3 schemes
- [x] Signature verification passes
- [x] APK installs on connected ADB device
- [x] App launches without "Root detected!" dialog
- [x] Any string entered in "Enter the Secret String" field shows "Success!"

---

## Notes

- The app package name is `owasp.mstg.uncrackable1` (from AndroidManifest.xml)
- The original app class is `sg.vantagepoint.uncrackable1.MainActivity`
- Root detection runs in `onCreate()` before the UI is shown
- Secret verification runs when user taps the "Verify" button in `MainActivity.verify()`
- The bypass modifies only Smali methods — no other app functionality is affected
- The key/keystore password is `password` (change before production use)

---

## Reference: Complete Command List

```bat
:: 1. Decompile
java -jar build-tools\apktool.jar d UnCrackable-Level1.apk -o app_decompiled -f --frame-path .\frame_cache

:: 2. JADX decompilation
bin\jadx.bat UnCrackable-Level1.apk -d app_java -r

:: 3. (Manual: edit app_decompiled/smali/sg/vantagepoint/a/c.smali)

:: 4. Rebuild
java -jar build-tools\apktool.jar b app_decompiled -o modified_app.apk

:: 5. Create keystore
keytool -genkey -v -keystore my-release-key.jks -keyalg RSA -keysize 2048 -validity 10000 -alias mykey -keypass password -storepass password -dname "CN=UnCrackable, OU=Testing, O=Security, L=City, ST=State, C=US"

:: 6. Zipalign
build-tools\android-13\zipalign.exe -v -p 4 modified_app.apk final_app.apk

:: 7. Sign
build-tools\android-13\apksigner.bat sign --ks my-release-key.jks --ks-pass pass:password --ks-key-alias mykey --key-pass pass:password --v4-signing-enabled false final_app.apk

:: 8. Verify
build-tools\android-13\apksigner.bat verify --verbose final_app.apk

:: 9. Install
adb uninstall owasp.mstg.uncrackable1
adb install final_app.apk
```
