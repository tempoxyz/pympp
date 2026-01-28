# mpay-python Spec Compliance Audit Report

**Date**: January 28, 2026  
**Scope**: mpay-python implementation vs IETF Payment Auth Spec (`draft-httpauth-payment-00`)  
**Auditor**: Amp (Oracle-assisted analysis)

---

## Executive Summary

The mpay-python SDK provides a clean, async-native implementation of the Payment HTTP Authentication Scheme. However, **several critical divergences from the IETF spec** exist that would cause interoperability issues with other compliant implementations and introduce security gaps.

| Severity | Count | Description |
|----------|-------|-------------|
| 🔴 Critical | 3 | Spec-breaking divergences in wire format |
| 🟠 High | 4 | Missing security requirements |
| 🟡 Medium | 5 | Missing optional but recommended features |
| 🔵 Low | 3 | Implementation bugs/quality issues |

---

## 🔴 Critical Findings

[fix]### C1. Credential Format Does Not Match Spec

**Spec Reference**: [Section 5.2](file:///Users/brendanryan/tempo/ietf-paymentauth-spec/specs/core/draft-httpauth-payment-00.md#L331-L390)

**Spec Requirement**: The Authorization credential MUST be a base64url-encoded JSON object containing:

```json
{
  "challenge": {
    "id": "...",
    "realm": "...",
    "method": "...",
    "intent": "...",
    "request": "<base64url>",
    "digest": "...",      // optional
    "expires": "..."      // optional
  },
  "source": "did:...",    // optional
  "payload": {...}
}
```

**Implementation**: [mpay/_parsing.py#L172-L203](file:///Users/brendanryan/tempo/mpay-python/src/mpay/_parsing.py#L172-L203)

```python
# Current format:
{
  "id": "...",
  "payload": {...},
  "source": "..."
}
```

**Impact**:

- Interoperability failure with other spec-compliant implementations
- Missing challenge echo prevents server-side integrity verification
- `realm`, `method`, `intent` cannot be validated

**Recommendation**: Restructure `Credential` to include nested `challenge` object with all original challenge parameters.

---

 [fix]### C2. Receipt Missing Required `method` Field

**Spec Reference**: [Section 5.3](file:///Users/brendanryan/tempo/ietf-paymentauth-spec/specs/core/draft-httpauth-payment-00.md#L392-L410)

**Spec Requirement**: Receipt MUST include:

| Field | Type | Description |
|-------|------|-------------|
| `status` | string | "success" or "failed" |
| `method` | string | Payment method used |
| `timestamp` | string | ISO 8601 settlement time |
| `reference` | string | Method-specific reference |

**Implementation**: [mpay/**init**.py#L79-L122](file:///Users/brendanryan/tempo/mpay-python/src/mpay/__init__.py#L79-L122)

The `Receipt` dataclass only has `status`, `timestamp`, `reference` - **missing `method`**.

**Impact**: Non-compliant receipts; clients cannot identify which payment method was used.

**Recommendation**: Add `method: str` field to `Receipt` dataclass and update parsing/formatting.

---

[fix] ### C3. No Challenge Binding Verification

**Spec Reference**: [Section 5.1.3](file:///Users/brendanryan/tempo/ietf-paymentauth-spec/specs/core/draft-httpauth-payment-00.md#L275-L285)

**Spec Requirement**:
> "Servers SHOULD bind the challenge `id` to the challenge parameters... Servers MUST verify that credentials present an `id` matching the expected binding."

**Implementation**: [mpay/server/verify.py#L15-L77](file:///Users/brendanryan/tempo/mpay-python/src/mpay/server/verify.py#L15-L77)

The implementation:

1. Generates a random challenge ID with `secrets.token_urlsafe(16)`
2. Does NOT store the challenge anywhere
3. Does NOT verify that the credential's ID corresponds to an issued challenge
4. Does NOT verify that challenge parameters match

**Impact**:

- Challenge substitution attacks possible
- Attacker can forge arbitrary challenge IDs
- No integrity protection for payment requests

**Recommendation**:

- Implement challenge storage (in-memory cache or pluggable store)
- Verify credential's challenge ID exists and parameters match
- Mark challenges as consumed after successful verification

---

## 🟠 High Severity Findings

### H1. No Replay Protection (Challenge Single-Use Enforcement)

**Spec Reference**: [Section 7.2](file:///Users/brendanryan/tempo/ietf-paymentauth-spec/specs/core/draft-httpauth-payment-00.md#L581-L588)

**Spec Requirement**:
> "A payment proof MUST be usable exactly once; subsequent attempts to use the same proof MUST be rejected."

**Implementation**: The server has no challenge state tracking. The same credential can be submitted multiple times.

**Note**: The Tempo `ChargeIntent` partially mitigates this by verifying on-chain transaction state, but:

1. Other intents/methods may not have this protection
2. Double-submission race conditions are still possible

**Recommendation**: Add challenge consumption tracking with atomic "verify-and-consume" semantics.

---

[fix] ### H2. No RFC 9457 Problem Details Error Responses

**Spec Reference**: [Section 4.2](file:///Users/brendanryan/tempo/ietf-paymentauth-spec/specs/core/draft-httpauth-payment-00.md#L156-L167)

**Spec Requirement**: Error details MUST be provided in response body using Problem Details (RFC 9457):

```json
{
  "type": "https://ietf.org/payment/problems/verification-failed",
  "title": "Payment Verification Failed",
  "status": 402,
  "detail": "Invalid payment proof."
}
```

**Implementation**: [mpay/server/decorator.py#L30-L45](file:///Users/brendanryan/tempo/mpay-python/src/mpay/server/decorator.py#L30-L45)

Returns only `WWW-Authenticate` header with `content=None` - no error body.

**Impact**: Clients cannot distinguish between different failure modes (malformed credential, expired challenge, verification failed).

**Recommendation**: Add RFC 9457 problem+json response bodies for all 402 cases.

---

[fix] ### H3. Missing `Cache-Control: no-store` on 402 Responses

**Spec Reference**: [Section 7.10](file:///Users/brendanryan/tempo/ietf-paymentauth-spec/specs/core/draft-httpauth-payment-00.md#L650-L661)

**Spec Requirement**:
> "Servers MUST send `Cache-Control: no-store` with 402 responses."

**Implementation**: The decorator only sets `WWW-Authenticate` header.

**Impact**: Challenges may be cached by proxies/CDNs, causing stale/reused challenges.

**Recommendation**: Add `Cache-Control: no-store` to all 402 responses.

---

### H4. No TLS Enforcement

**Spec Reference**: [Section 7.1](file:///Users/brendanryan/tempo/ietf-paymentauth-spec/specs/core/draft-httpauth-payment-00.md#L556-L578)

**Spec Requirement**:
> "Implementations MUST use TLS when transmitting Payment challenges and credentials... Clients MUST NOT send Payment credentials over unencrypted HTTP."

**Implementation**: The client transport has no scheme validation - will send credentials over HTTP.

**Impact**: Credential exposure to MITM attacks on misconfigured deployments.

**Recommendation**:

- Client: Reject or warn when `request.url.scheme != "https"`
- Document TLS requirement prominently

---

## 🟡 Medium Severity Findings

[fix] ### M1. Client Does Not Check Challenge Expiry

**Spec Reference**: [Section 5.1.2](file:///Users/brendanryan/tempo/ietf-paymentauth-spec/specs/core/draft-httpauth-payment-00.md#L264-L267)

**Spec Requirement**:
> "Clients MUST NOT submit credentials for expired challenges."

**Implementation**: [mpay/client/transport.py](file:///Users/brendanryan/tempo/mpay-python/src/mpay/client/transport.py)

The client transport parses the challenge but never checks `challenge.expires` before creating/sending credentials.

**Recommendation**: Check `challenge.expires` and skip payment if expired.

---

[fix] ### M2. Server Does Not Set `expires` on Challenges

**Implementation**: [mpay/server/verify.py#L79-L90](file:///Users/brendanryan/tempo/mpay-python/src/mpay/server/verify.py#L79-L90)

`_create_challenge()` never sets the `expires` field. Per spec, servers SHOULD include this parameter.

**Recommendation**: Add configurable challenge TTL with default (e.g., 5 minutes).

---

[fix] ### M3. Multiple WWW-Authenticate Headers Not Handled

**Spec Reference**: [Appendix A, Multiple Payment Options](file:///Users/brendanryan/tempo/ietf-paymentauth-spec/specs/core/draft-httpauth-payment-00.md#L904-L921)

**Spec Requirement**: Servers MAY return multiple Payment challenges; clients should select one.

**Implementation**: [mpay/client/transport.py#L68](file:///Users/brendanryan/tempo/mpay-python/src/mpay/client/transport.py#L68)

```python
www_auth = response.headers.get("www-authenticate")  # Only gets first
```

**Impact**: Cannot handle servers offering multiple payment methods.

**Recommendation**: Use `response.headers.get_list("www-authenticate")` and iterate.

---

[fix] ### M4. Server Does Not Validate `realm` Parameter

The `realm` is passed to `verify_or_challenge()` but only used for generating challenges, never validated against incoming credentials.

**Recommendation**: When challenge binding is implemented, include realm verification.

---

[fix] ### M5. `VerificationError` Not Caught in Server Flow

**Implementation**: [mpay/server/verify.py#L75-L76](file:///Users/brendanryan/tempo/mpay-python/src/mpay/server/verify.py#L75-L76)

```python
receipt: Receipt = await intent.verify(credential, request)
return (credential, receipt)
```

If `intent.verify()` raises `VerificationError`, it propagates as an unhandled exception (likely 500).

**Recommendation**: Catch `VerificationError` and return fresh challenge with appropriate problem details.

---

## 🔵 Low Severity Findings

### L1. Base64 Decode May Raise Unexpected Exception

**Implementation**: [mpay/_parsing.py#L55-L63](file:///Users/brendanryan/tempo/mpay-python/src/mpay/_parsing.py#L55-L63)

```python
except (ValueError, json.JSONDecodeError):
    raise ParseError("Invalid base64 or JSON encoding") from None
```

`base64.urlsafe_b64decode()` can raise `binascii.Error` which is not caught.

**Recommendation**: Add `binascii.Error` to the exception tuple.

---

### L2. Client Retry May Fail with Streamed Bodies

**Implementation**: [mpay/client/transport.py#L89-L97](file:///Users/brendanryan/tempo/mpay-python/src/mpay/client/transport.py#L89-L97)

For POST/PUT with streaming bodies, reusing `request.stream` after the initial 402 may fail (stream already consumed).

**Recommendation**: Document limitation or buffer body before initial request.

---

### L3. Auth Param Parsing is Non-Strict

**Implementation**: [mpay/_parsing.py#L78-L86](file:///Users/brendanryan/tempo/mpay-python/src/mpay/_parsing.py#L78-L86)

The regex-based parsing silently ignores malformed segments rather than rejecting them per strict RFC 9110 ABNF.

**Recommendation**: Consider stricter parsing or document permissive behavior.

---

## Compliance Summary Matrix

| Spec Requirement | Status | Notes |
|------------------|--------|-------|
| WWW-Authenticate format | ✅ Compliant | Correct auth-param syntax |
| Authorization credential format | ❌ Non-compliant | Missing `challenge` object |
| Payment-Receipt format | ❌ Non-compliant | Missing `method` field |
| Challenge binding (SHOULD) | ❌ Missing | No binding verification |
| Challenge single-use (MUST) | ❌ Missing | No replay protection |
| Expires validation | ⚠️ Partial | Server intent checks, client doesn't |
| Cache-Control: no-store | ❌ Missing | Not set on 402 responses |
| RFC 9457 error responses | ❌ Missing | No problem details |
| TLS requirement | ❌ Not enforced | No scheme validation |
| Multiple challenges | ⚠️ Partial | Server can issue, client ignores extras |

---

## Recommendations Priority

### Immediate (Breaking Changes - v2.0)

1. **C1**: Restructure credential format to include `challenge` object
2. **C2**: Add `method` field to Receipt
3. **H2**: Add RFC 9457 problem detail responses

### High Priority (Security)

4. **C3/H1**: Implement challenge store with binding and single-use enforcement
2. **H3**: Add `Cache-Control: no-store` header
3. **H4**: Add TLS scheme validation (opt-out for testing)

### Medium Priority

7. **M1**: Client expiry check before paying
2. **M2**: Add default challenge expiry
3. **M3**: Handle multiple WWW-Authenticate headers
4. **M5**: Catch VerificationError and return proper 402

### Low Priority

11. **L1**: Fix base64 exception handling
2. **L2**: Document streaming body limitation
3. **L3**: Consider stricter parsing

---

## Appendix: Spec-Compliant Credential Structure

For reference, here's what a compliant credential should look like:

```python
@dataclass(frozen=True, slots=True)
class Credential:
    challenge: ChallengeEcho  # Full challenge parameters
    payload: dict[str, Any]
    source: str | None = None

@dataclass(frozen=True, slots=True)  
class ChallengeEcho:
    id: str
    realm: str
    method: str
    intent: str
    request: str  # Keep as base64url string, not decoded
    digest: str | None = None
    expires: str | None = None
```

Wire format:

```json
{
  "challenge": {
    "id": "x7Tg2pLqR9mKvNwY3hBcZa",
    "realm": "api.example.com",
    "method": "tempo",
    "intent": "charge",
    "request": "eyJhbW91bnQiOi4uLn0",
    "expires": "2025-01-15T12:05:00Z"
  },
  "payload": {
    "type": "transaction",
    "signature": "0x..."
  },
  "source": "did:pkh:eip155:1:0x742d..."
}
```
