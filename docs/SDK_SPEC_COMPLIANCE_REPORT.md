# SDK Spec Compliance Report: mpay-python

**Audit Date:** 2026-01-28
**Spec Version:** [mpay-sdks/SPEC.md](../../mpay-sdks/SPEC.md)
**SDK Version:** mpay-python (current main branch)

## Executive Summary

**Overall Compliance: PARTIAL (FAILS SERVER REQUIREMENTS)**

mpay-python implements the core header types/parsing, a 402-aware httpx transport, and a Tempo "charge" intent with client method. However, the server-side implementation has critical spec violations: challenge IDs are not bound to parameters, credential.id verification is absent, and Challenge.expires is unused.

| Category | Status | Notes |
|----------|--------|-------|
| Core Types | ✅ Pass | Challenge, Credential, Receipt implemented |
| Methods (tempo) | ⚠️ Partial | Client works; server verification unsafe |
| Intents (charge) | ⚠️ Partial | Missing Intent.challenge() API |
| Client Transport | ⚠️ Partial | Basic flow works; robustness issues |
| Server | ❌ Fail | Challenge binding and verification gaps |

---

## 1. Core Types (draft-ietf-httpauth-payment §5)

### ✅ COMPLIANT

**What's Implemented:**
- `Challenge` with `id`, `method`, `intent`, `request`, optional `digest`, `expires`, `description`
- `Credential` with `id`, `payload`, optional `source`
- `Receipt` with `status`, `timestamp`, `reference` + header encode/decode
- Header parsing/formatting for:
  - `WWW-Authenticate: Payment ...`
  - `Authorization: Payment <b64json>`
  - `Payment-Receipt: <b64json>`

**Minor Gaps:**
- `parse_www_authenticate()` requires `realm` but discards it (Challenge has no `realm` field)
- `Challenge.expires` is a string and is never parsed/validated in core/server flow

**Files:**
- [`src/mpay/__init__.py`](../src/mpay/__init__.py) — Core types
- [`src/mpay/_parsing.py`](../src/mpay/_parsing.py) — Header parsing

---

## 2. Methods (MUST implement `tempo`)

### ⚠️ PARTIALLY COMPLIANT

**What's Implemented:**
- Client-side: `TempoMethod` with `name = "tempo"` and `create_credential()`
- Server-side: `ChargeIntent.verify()` for Tempo payments
- Credential payload supports `{type:"transaction"}` and `{type:"hash"}`

**Gaps:**

| Issue | Severity | Description |
|-------|----------|-------------|
| Client only creates transaction credentials | Low | No client helper for `hash`-type credentials |
| **Unsafe transaction verification** | **Critical** | Server may sponsor/broadcast tx before validating it matches request parameters. Verification of logs happens only after inclusion. |

**Critical Safety Issue:**
In `ChargeIntent._verify_transaction()`, the server may forward a raw signed transaction to a fee payer or broadcast it **before validating** it matches request parameters. This enables:
- Attacker submits a transaction credential that doesn't match the requested payment
- Server sponsors/broadcasts it, paying gas for an unwanted action
- Verification fails afterwards but damage is done

**Recommendation:** Decode/inspect the signed transaction before sponsoring to ensure it is a TIP-20 transfer matching `request.recipient`, `request.amount`, and `request.currency`.

**Files:**
- [`src/mpay/methods/tempo/client.py`](../src/mpay/methods/tempo/client.py)
- [`src/mpay/methods/tempo/intents.py`](../src/mpay/methods/tempo/intents.py)

---

## 3. Intents (MUST implement `charge`)

### ⚠️ PARTIALLY COMPLIANT

**What's Implemented:**
- `ChargeIntent` with `name = "charge"` and `verify()`
- Temporal expiry validation on `request.expires`

**Gap:**
- **SPEC requires:** `Intent.challenge(request: object) -> Challenge`
- **Current implementation:** There is no `Intent.challenge` method in the `Intent` protocol
- Challenge creation is done by `verify_or_challenge()` via `_create_challenge()`, not by intent

**Files:**
- [`src/mpay/server/intent.py`](../src/mpay/server/intent.py)
- [`src/mpay/methods/tempo/intents.py`](../src/mpay/methods/tempo/intents.py)

---

## 4. Client: 402 Transport

### ⚠️ PARTIALLY COMPLIANT

**What's Implemented (matches SPEC retry steps 1–6):**
1. ✅ Make initial request
2. ✅ On 402 response, parse `WWW-Authenticate` header
3. ✅ Match challenge `method` to a configured payment method
4. ✅ Call `method.create_credential(challenge)` to produce a credential
5. ✅ Retry request with `Authorization: Payment <credential>` header
6. ⚠️ Return final response (receipt not parsed automatically)

**Gaps:**

| Issue | Severity | Description |
|-------|----------|-------------|
| WWW-Authenticate parsing too strict | Medium | Only checks if header starts with "Payment ". Servers may send multiple `WWW-Authenticate` headers or combined values (e.g. `Bearer ..., Payment ...`). |
| Request replay not robust | Medium | Uses `stream=request.stream` for retry. For non-idempotent requests or streaming bodies, this may fail after first send (body consumed). |
| Receipt not exposed | Low | Returns raw `httpx.Response`, does not parse/expose `Payment-Receipt` into a `Receipt` object automatically. |

**Recommendation:**
- Parse all `WWW-Authenticate` headers using `response.headers.get_list("www-authenticate")`
- Buffer request body for non-idempotent methods before first send

**Files:**
- [`src/mpay/client/transport.py`](../src/mpay/client/transport.py)

---

## 5. Server: Challenge Generation and Verification

### ❌ NOT COMPLIANT

This is the primary area of non-compliance.

### 5.1 Challenge Generation

**SPEC Requirements:**
- ❌ **MUST generate unique id bound to parameters** — Current: `secrets.token_urlsafe(16)` (random, not bound)
- ✅ **MUST include method, intent, request** — Yes
- ❌ **SHOULD include expires** — Not set by `_create_challenge()`

### 5.2 Verification

**SPEC Requirements:**
| Requirement | Status | Notes |
|-------------|--------|-------|
| Validate challenge.id matches expected binding | ❌ | No check; no binding mechanism |
| Validate challenge parameters match original request | ❌ | No mechanism; intent.verify only sees request |
| Validate expires has not passed | ⚠️ | Only checks `request.expires`, not `Challenge.expires` |
| Verify payload according to payment method spec | ⚠️ | Partial; unsafe ordering (broadcast before validation) |
| Return Receipt on success, raise error on failure | ⚠️ | Returns `Receipt.failed` instead of raising for some failures |

**Current Flow in `verify_or_challenge()`:**
```python
# No binding check on credential.id
receipt: Receipt = await intent.verify(credential, request)
return (credential, receipt)
```

**What's Missing:**
1. No stored or computed challenge binding
2. No verification that `credential.id` corresponds to a valid challenge for this request
3. No challenge-level expiry validation

**Files:**
- [`src/mpay/server/verify.py`](../src/mpay/server/verify.py)

---

## Compliance Checklist Summary

| Requirement | Status |
|-------------|--------|
| Challenge MUST generate unique id bound to parameters | ❌ Not bound; random only |
| Challenge MUST include method, intent, request | ✅ Yes |
| Challenge SHOULD include expires | ❌ Not included by generator |
| Verification MUST validate challenge.id matches expected binding | ❌ No check; no binding mechanism |
| Verification MUST validate challenge parameters match original request | ❌ No mechanism |
| Verification MUST validate expires has not passed | ⚠️ Only for `request.expires`, not `Challenge.expires` |
| Verification MUST verify payload according to payment method spec | ⚠️ Partially; unsafe ordering |
| Verification MUST return Receipt on success or raise error on failure | ⚠️ Returns `Receipt.failed` on some failures |

---

## Remediation Recommendations

### High Priority (Security/Compliance Critical)

#### 1. Implement Parameter-Bound Challenge IDs (Effort: M ~3–6h)

**Option A: Stateless HMAC Binding**
```python
import hmac
import hashlib
import json

def _create_challenge(method: str, intent_name: str, request: dict, expires: str, secret: bytes) -> Challenge:
    canonical = json.dumps({"m": method, "i": intent_name, "r": request, "e": expires}, sort_keys=True)
    challenge_id = base64.urlsafe_b64encode(
        hmac.new(secret, canonical.encode(), hashlib.sha256).digest()
    ).decode().rstrip("=")
    return Challenge(id=challenge_id, method=method, intent=intent_name, request=request, expires=expires)
```

**Option B: Stateful Storage**
- Store challenges with TTL (Redis/in-memory)
- Map `challenge.id → (method, intent, request, expires)`
- Look up on verification

#### 2. Add Challenge Binding Verification (Effort: M ~2–4h)

Modify `verify_or_challenge()`:
```python
# Recompute expected challenge_id from (method, intent, request, expires)
expected_id = _compute_challenge_id(method_name, intent.name, request, expires)
if credential.id != expected_id:
    return _create_challenge(...)  # Invalid credential, issue new challenge

# Check expiry
if datetime.fromisoformat(expires) < datetime.now(UTC):
    return _create_challenge(...)
```

#### 3. Fix Tempo Transaction Verification Ordering (Effort: M ~3–6h)

Before sponsoring/broadcasting in `_verify_transaction()`:
- Decode the signed transaction
- Validate it's a TIP-20 transfer to `request.recipient` of `request.amount` on `request.currency`
- Only submit once validated

### Medium Priority

#### 4. Harden 402 Transport Header Handling (Effort: M ~3–6h)
- Parse all `WWW-Authenticate` headers, locate the `Payment` challenge
- Buffer request body for reliable retry

#### 5. Align Failure Behavior with Spec (Effort: S ~1–2h)
- Decide: if tx reverted, should that raise `VerificationError` or return `Receipt.failed`?
- SPEC says "raise error on failure"

### Low Priority

#### 6. Add Intent.challenge() API (Effort: S ~2h)
- Add `challenge(request: dict) -> Challenge` method to Intent protocol
- Move challenge generation logic from `verify_or_challenge()` to intents

---

## Risk Assessment

| Risk | Severity | Impact |
|------|----------|--------|
| Gas drain via unvalidated transaction sponsoring | Critical | Attacker can make server pay gas for arbitrary transactions |
| Credential replay/forgery due to unbound challenge IDs | High | Attacker could potentially reuse or forge credentials |
| 402 flow failures due to non-robust header parsing | Medium | Legitimate payments may fail in mixed-auth environments |
| Request body not replayable on retry | Medium | Non-idempotent requests with streaming bodies may fail |

---

## Conclusion

mpay-python has a solid foundation with correct core types and parsing, but **fails server-side spec compliance** due to missing challenge binding and verification. The unsafe transaction verification ordering presents a critical security risk.

**Estimated effort to reach compliance:** M–L (1–2 days)

Priority order:
1. Fix unsafe transaction verification ordering (Critical security)
2. Implement parameter-bound challenge IDs
3. Add challenge binding verification
4. Harden client transport
5. Add Intent.challenge() API
