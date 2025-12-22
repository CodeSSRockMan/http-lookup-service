# Security Architecture

This document explains the security design of the HTTP Lookup Service, focusing on the order of operations in the validation pipeline and why this order is critical for preventing bypass attacks.

## Table of Contents

1. [Security Pipeline Overview](#security-pipeline-overview)
2. [Order of Operations](#order-of-operations)
3. [Why This Order Matters](#why-this-order-matters)
4. [Attack Prevention Examples](#attack-prevention-examples)
5. [Security Best Practices](#security-best-practices)
6. [Known Limitations](#known-limitations)

---

## Security Pipeline Overview

Every incoming URL request goes through a **5-step security pipeline** before returning a response:

```
┌─────────────────────────────────────────────────────────┐
│                    INCOMING REQUEST                     │
│         /urlinfo/1/{hostname_and_port}/{path}           │
└────────────────────┬────────────────────────────────────┘
                     │
                     ▼
           ┌─────────────────┐
           │  STEP 1: DECODE │  ← URL decode (e.g., %27 → ')
           └────────┬─────────┘
                    │
                    ▼
         ┌──────────────────────┐
         │ STEP 2: VALIDATE     │  ← Check URL format & regex
         └──────────┬───────────┘
                    │
                    ▼
      ┌──────────────────────────────┐
      │ STEP 3: PATTERN MATCH        │  ← Check for SQLi, XSS, etc.
      └──────────────┬───────────────┘
                     │
                     ▼
           ┌─────────────────────┐
           │ STEP 4: SANITIZE    │  ← Remove control chars
           └──────────┬──────────┘
                      │
                      ▼
         ┌────────────────────────────┐
         │ STEP 5: DATABASE LOOKUP    │  ← Check domain reputation
         └────────────┬───────────────┘
                      │
                      ▼
              ┌───────────────┐
              │   RESPONSE    │
              └───────────────┘
```

---

## Order of Operations

### Step 1: **DECODE** (URL Decoding)
**Function:** `decode_url_parts(url)`

Converts URL-encoded characters to their actual values:
- `%27` → `'`
- `%3C` → `<`
- `%20` → ` `
- `%2F` → `/`

**Why First?**
Attackers can encode malicious characters to bypass pattern matching and validation. For example:
- `%27OR%201%3D1` looks harmless when encoded
- After decoding: `'OR 1=1` is clearly a SQL injection attempt

**Critical:** This MUST happen before validation and pattern matching, otherwise encoded attacks will slip through.

---

### Step 2: **VALIDATE** (Format & Regex Check)
**Function:** `validate_url_regex(url)`

Checks if the decoded URL matches valid HTTP/HTTPS format:
- Valid scheme: `http://` or `https://`
- Valid hostname (domain or IP)
- Valid port range: 1-65535
- Proper URL structure

**Why Second?**
After decoding, we need to ensure the URL is structurally valid before processing further. Invalid URLs are rejected immediately.

**Example Rejections:**
- `ftp://example.com` (invalid scheme)
- `http://example.com:99999` (port out of range)
- `http://` (missing hostname)

---

### Step 3: **PATTERN MATCH** (Malicious Content Detection)
**Function:** `check_malicious_patterns(url)`

Checks the decoded URL against a database of known malicious patterns:
- SQL Injection: `' OR 1=1`, `UNION SELECT`, etc.
- Cross-Site Scripting (XSS): `<script>`, `javascript:`, etc.
- Path Traversal: `../`, `..\\`, etc.
- Command Injection: `; rm -rf`, `| cat /etc/passwd`, etc.

**Why Third?**
Must check the **decoded** content to detect encoded attacks. Checking before decoding would miss attacks like:
- `%3Cscript%3E` (encoded `<script>`)
- `%27%20OR%201%3D1` (encoded `' OR 1=1`)

**Database:** Patterns are stored in `malicious_queries` table with severity levels (critical, high, medium, low).

---

### Step 4: **SANITIZE** (Control Character Removal)
**Function:** `sanitize_url(url)`

Removes control characters as a safety measure:
- Null bytes (`\x00`)
- Newlines (`\n`, `\r`)
- Tabs (`\t`)
- Other control characters

**Why Fourth?**
This is a **defensive** measure, not a security measure. By this point:
- URL has been decoded
- URL has been validated
- Malicious patterns have been checked

Sanitization is a last-resort cleanup for edge cases and doesn't replace the security checks above.

**Important:** Sanitization is NOT for security. It's for preventing potential issues with downstream systems.

---

### Step 5: **DATABASE LOOKUP** (Domain Reputation Check)
**Function:** `lookup_domain(hostname)`

Checks the domain's reputation in the database:
- **Safe:** Domain is known and trusted
- **Malicious:** Domain is known to be malicious (malware, phishing, etc.)
- **Suspicious:** Domain has suspicious activity
- **Blacklisted:** Domain is on a blacklist
- **Unknown:** Domain not in database (neutral)

**Why Last?**
After all validation and pattern checks, we check if the domain itself is known to be malicious.

**Database:** Domain reputation stored in `domains` table with threat levels.

---

## Why This Order Matters

### ❌ **WRONG Order: Sanitize → Decode → Validate**

If we sanitize before decoding:
```python
# WRONG ORDER
sanitized = sanitize_url("http://evil.com/?attack=%27OR%201%3D1")
# Result: "http://evil.com/?attack=%27OR%201%3D1" (still encoded)
decoded = decode_url_parts(sanitized)
# Result: "http://evil.com/?attack='OR 1=1" (now decoded, but too late!)
```

**Problem:** The malicious pattern `'OR 1=1` was already checked in its encoded form and passed validation.

---

### ❌ **WRONG Order: Validate → Decode**

If we validate before decoding:
```python
# WRONG ORDER
if validate_url_regex("http://evil.com/?attack=%3Cscript%3E"):
    # Passes validation (looks like a normal URL)
    decoded = decode_url_parts("http://evil.com/?attack=%3Cscript%3E")
    # Result: "http://evil.com/?attack=<script>" (XSS attack revealed too late!)
```

**Problem:** The XSS attack was hidden by encoding and bypassed validation.

---

### ✅ **CORRECT Order: Decode → Validate → Pattern Match → Sanitize → DB Lookup**

```python
# CORRECT ORDER
decoded = decode_url_parts("http://evil.com/?attack=%27OR%201%3D1")
# Result: "http://evil.com/?attack='OR 1=1" (decoded FIRST)

if not validate_url_regex(decoded):
    # Check format on decoded content
    raise Exception("Invalid URL")

malicious_info = check_malicious_patterns(decoded)
# NOW we check the actual decoded content: "'OR 1=1"
# DETECTED: SQL Injection pattern found!
```

**Success:** The attack is detected because we decoded first, then checked the actual content.

---

## Attack Prevention Examples

### Example 1: Encoded SQL Injection

**Attack URL:**
```
http://example.com/search?q=%27%20OR%201%3D1
```

**Pipeline Processing:**
1. **Decode:** `http://example.com/search?q=' OR 1=1`
2. **Validate:** ✅ Valid URL format
3. **Pattern Match:** ⚠️ **DETECTED** - SQL injection pattern `' OR 1=1`
4. **Response:** `safe: false, malicious: true, detected_threats: ["SQL Injection"]`

**Result:** Attack blocked ✅

---

### Example 2: Encoded XSS Attack

**Attack URL:**
```
http://example.com/page?name=%3Cscript%3Ealert(1)%3C%2Fscript%3E
```

**Pipeline Processing:**
1. **Decode:** `http://example.com/page?name=<script>alert(1)</script>`
2. **Validate:** ✅ Valid URL format
3. **Pattern Match:** ⚠️ **DETECTED** - XSS pattern `<script>`
4. **Response:** `safe: false, malicious: true, detected_threats: ["Cross-Site Scripting (XSS)"]`

**Result:** Attack blocked ✅

---

### Example 3: Encoded Path Traversal

**Attack URL:**
```
http://example.com/files/%2e%2e%2f%2e%2e%2fetc%2fpasswd
```

**Pipeline Processing:**
1. **Decode:** `http://example.com/files/../../etc/passwd`
2. **Validate:** ✅ Valid URL format
3. **Pattern Match:** ⚠️ **DETECTED** - Path traversal pattern `../`
4. **Response:** `safe: false, malicious: true, detected_threats: ["Path Traversal"]`

**Result:** Attack blocked ✅

---

### Example 4: Clean URL

**Clean URL:**
```
http://example.com/api/users?page=2&limit=10
```

**Pipeline Processing:**
1. **Decode:** `http://example.com/api/users?page=2&limit=10`
2. **Validate:** ✅ Valid URL format
3. **Pattern Match:** ✅ No threats detected
4. **Sanitize:** ✅ No control characters
5. **DB Lookup:** Domain `example.com` → unknown (neutral)
6. **Response:** `safe: true, malicious: false`

**Result:** URL allowed ✅

---

## Security Best Practices

### 1. **Defense in Depth**
Multiple layers of security:
- Decoding reveals hidden content
- Validation ensures proper format
- Pattern matching detects known attacks
- Sanitization removes edge cases
- Database checks domain reputation

### 2. **Fail Secure**
Default to "unsafe" if any check fails:
- Invalid URL format → reject
- Malicious pattern detected → mark unsafe
- Known malicious domain → mark unsafe

### 3. **Regular Updates**
Keep the malicious patterns database updated:
- Add new attack signatures
- Update known malicious domains
- Review threat intelligence feeds

### 4. **Logging and Monitoring**
Log all detected attacks:
- URL that triggered detection
- Type of attack detected
- Timestamp
- Source IP (if available)

### 5. **Rate Limiting** (Future Enhancement)
Implement rate limiting to prevent:
- Brute force pattern testing
- Database enumeration
- DoS attacks

---

## Known Limitations

### 1. **Zero-Day Attacks**
The pattern matching system only detects **known** attack patterns. Novel or obfuscated attacks may bypass detection.

**Mitigation:** Regularly update the malicious patterns database with new signatures.

### 2. **Domain Reputation Coverage**
The database only contains known domains. New malicious domains won't be detected until added to the database.

**Mitigation:** Integrate with threat intelligence feeds for real-time updates.

### 3. **False Positives**
Some legitimate URLs may trigger pattern matching (e.g., SQL tutorial sites with query examples).

**Mitigation:** 
- Fine-tune patterns to reduce false positives
- Implement a whitelist for known safe domains
- Provide context in responses (severity level, detected pattern)

### 4. **Performance**
Each request requires:
- URL decoding
- Regex validation
- Database pattern matching (up to N patterns)
- Database domain lookup

**Mitigation:**
- Implement Redis caching for frequent lookups
- Index database tables properly
- Use async database operations (already implemented)

### 5. **Read-Only Database**
Currently, the system is read-only and doesn't update the database based on detected attacks.

**Future Enhancement:**
- Add write endpoints to update domain reputation
- Implement machine learning for anomaly detection
- Auto-add detected malicious domains to blacklist

---

## Conclusion

The **Decode → Validate → Pattern Match → Sanitize → DB Lookup** order is critical for security:

1. **Decode first** to reveal hidden attacks
2. **Validate** to ensure proper format
3. **Pattern match** to detect known attacks on decoded content
4. **Sanitize** as a defensive measure
5. **DB lookup** to check domain reputation

Changing this order would create security vulnerabilities that attackers could exploit using URL encoding and other obfuscation techniques.

---

**Last Updated:** 2025-01-01  
**Reviewed By:** Security Team  
**Next Review:** Q2 2025
