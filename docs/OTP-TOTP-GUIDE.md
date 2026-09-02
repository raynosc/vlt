# Complete Guide to Two-Factor Authentication (2FA) and TOTP in `vlt`

[English](OTP-TOTP-GUIDE.md) | [Español](es/OTP-TOTP-GUIDE.md)

This guide explains **what TOTP is**, **how it works**, **its security benefits**, and **how to use it within `vlt`**.

---

## 1. What is 2FA, OTP, and TOTP?

### A. 2FA (Two-Factor Authentication)
A security mechanism requiring **two distinct forms of identification** before granting account access:
1. **First Factor (Something you know)**: Username and master password.
2. **Second Factor (Something you have)**: `vlt` generating a time-limited one-time code.

### B. TOTP (Time-based One-Time Password / RFC 6238)
The industry standard used by GitHub, Google, AWS, Microsoft, and others. It computes a fresh 6-digit code every **30 seconds** by combining:
* A **shared secret key** (Base32 seed).
* The **current Unix timestamp** (in 30-second steps).

```
   ┌────────────────────────────────┐
   │ Secret Seed (Base32)           │
   │ e.g.: JBSWY3DPEHPK3PXP         │
   └───────────────┬────────────────┘
                   │
                   ├────────► [ HMAC-SHA1 Algorithm ] ──► 6-Digit Code: "482 910"
                   │                                      (Valid for 30 seconds)
   ┌───────────────┴────────────────┐
   │ Current Time (30s window)      │
   └────────────────────────────────┘
```

> [!NOTE]
> **No Internet Connection Required**: The code is computed mathematically in local client memory.

---

## 2. Advantages of TOTP vs SMS

| Feature | SMS Codes | TOTP in `vlt` (RFC 6238) |
| :--- | :--- | :--- |
| **Security** | ❌ Vulnerable to SIM-swapping and cellular intercept. | ✅ Immune to cellular interception. Seeds are encrypted with AES-256-GCM client-side. |
| **Availability** | ❌ Requires cellular coverage and roaming signal. | ✅ Works 100% offline and in airplane mode. |
| **Privacy** | ❌ Mobile carriers can log metadata. | ✅ Zero-Knowledge. |

---

## 3. Usage in `vlt`

### Adding a TOTP Secret via CLI
```bash
# Add a TOTP seed
vlt add github-work --type totp --otp-secret "JBSWY3DPEHPK3PXP"

# Or parse an otpauth:// QR code URL directly
vlt add aws-root --type totp --otp-url "otpauth://totp/AWS:admin?secret=JBSWY3DPEHPK3PXP&issuer=Amazon"
```

### Generating Codes
```bash
# Get current 6-digit code
vlt otp github-work
```
