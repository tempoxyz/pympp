# mpay-python SDK Spec Compliance Audit

**Audit Date:** January 28, 2026  
**Specification:** [mpay-sdks/SPEC.md](https://github.com/tempoxyz/mpay-sdks/blob/main/SPEC.md)  
**Scope:** SDK specification compliance review

## Executive Summary

The mpay-python SDK provides the correct **structure** for a conformant implementation—core types, HTTP client transport, server verification, and Tempo method—but has **critical spec violations** in challenge binding and credential verification that undermine the protocol's security guarantees.

| Category | Status | Severity |
|----------|--------|----------|
| Core Types | ⚠️ Partial | Low |
| Client 402 Transport | ⚠️ Partial | Medium |
| Server Challenge Generation | ❌ Non-conformant | **Critical** |
| Server Verification | ❌ Non-conformant | **Critical** |
| Tempo Method | ✅ Conformant | - |
| Charge Intent | ⚠️ Partial | Medium |
| Transport Integrations | ✅ Conformant | - |

---

## Critical Issues

[fix] ### 1. Challenge ID Not Bound to Parameters (SPEC VIOLATION)

**Spec Requirement:**
> Challenge "MUST generate a unique `id` bound to the challenge parameters"

**Current Implementation ([server/verify.py#L79-L90](file:///Users/brendanryan/tempo/mpay-python/src/mpay/server/verify.py#L79-L90)):**

```python
def _create_challenge(method: str, intent_name: str, request: dict[str, Any]) -> Challenge:
    return Challenge(
        id=secrets.token_urlsafe(16),  # ❌ Random, not bound to parameters
        method=method,
        intent=intent_name,
        request=request,
    )
```

**Impact:** Challenge IDs are purely random and have no cryptographic binding to the challenge parameters. This breaks the server's ability to verify that a credential corresponds to a specific challenge without stateful storage.

**Recommendation:** Compute `id` as `base64url(HMAC(server_secret, canonical({method, intent, request, expires})))`.

---

[fix] ### 2. Credential ID Not Validated (SPEC VIOLATION)

**Spec Requirement:**
> Verification "MUST validate the `challenge.id` matches the expected binding"

**Current Implementation ([server/verify.py#L62-L76](file:///Users/brendanryan/tempo/mpay-python/src/mpay/server/verify.py#L62-L76)):**

```python
if authorization is None:
    return _create_challenge(method_name, intent.name, request)
# ...
credential = Credential.from_authorization(authorization)
receipt: Receipt = await intent.verify(credential, request)  # ❌ credential.id never checked
return (credential, receipt)
```

**Impact:** Credentials can be replayed against different request parameters than originally challenged. There is no verification that `credential.id` matches any expected value.

**Recommendation:** Before calling `intent.verify()`, recompute the expected challenge ID from current request parameters and compare to `credential.id`.

---

[fix] ### 3. Challenge Parameters Not Validated (SPEC VIOLATION)

**Spec Requirement:**
> Verification "MUST validate `challenge` parameters match the original request"

**Current Implementation:** No comparison is made between the original challenge request parameters and what the credential claims to be paying for.

**Impact:** A valid credential for one payment can be applied to a different payment request.

---

### 4. Challenge `expires` Not Implemented (SPEC VIOLATION)

**Spec Requirement:**
> Challenge "SHOULD include `expires` for time-limited challenges"  
> Verification "MUST validate `expires` has not passed"

**Current Implementation:**

- `_create_challenge()` never sets `expires`
- `verify_or_challenge()` never checks challenge expiration
- `ChargeIntent` checks `request.expires` (a different field in the request payload), not challenge expiration

**Impact:** Challenges never expire at the protocol level, enabling indefinite credential validity.

---

## Medium Severity Issues

[fix] ### 5. Request Body Not Replayed on 402 Retry

**Location:** [client/transport.py#L89-L96](file:///Users/brendanryan/tempo/mpay-python/src/mpay/client/transport.py#L89-L96)

```python
retry_request = httpx.Request(
    method=request.method,
    url=request.url,
    headers=headers,
    stream=request.stream,  # ⚠️ Stream may be consumed
    extensions=request.extensions,
)
```

**Impact:** POST/PUT requests with bodies may fail silently on retry because the stream is already consumed.

**Recommendation:** Buffer request content before first send; rebuild retry with `content=...`.

---

[fix] ### 6. Multiple WWW-Authenticate Headers Not Supported

**Location:** [client/transport.py#L68-L69](file:///Users/brendanryan/tempo/mpay-python/src/mpay/client/transport.py#L68-L69)

```python
www_auth = response.headers.get("www-authenticate")
if not www_auth or not www_auth.lower().startswith("payment "):
```

**Impact:** Servers may return multiple `WWW-Authenticate` headers or combine multiple schemes. The transport only handles a single Payment challenge.

**Recommendation:** Parse all `WWW-Authenticate` headers/values and select the first matching supported method.

---

[fix] ### 7. Intent.challenge() Method Not Implemented

**Spec Requirement:**
> "SDKs MUST provide a way to generate challenges: `Intent.challenge(request) -> Challenge`"

**Current Implementation:** Challenge generation is centralized in `verify_or_challenge()` using `_create_challenge()`. The `Intent` protocol does not define or require a `challenge()` method.

**Impact:** Intents cannot customize challenge generation; limits extensibility for future intents.

---

[fix] ### 8. ChargeIntent Payer Identity Not Verified

**Location:** [methods/tempo/intents.py#L192-L234](file:///Users/brendanryan/tempo/mpay-python/src/mpay/methods/tempo/intents.py#L192-L234)

The `_verify_transfer_logs()` method accepts an `expected_sender` parameter but it's never used:

```python
def _verify_transfer_logs(
    self, receipt: dict, request: ChargeRequest, expected_sender: str | None = None
) -> bool:
```

**Impact:** No verification that `Credential.source` (the payer DID) matches the transaction sender.

---

[fix] ### 9. Debug Prints in Library Code

**Location:** [methods/tempo/intents.py#L288](file:///Users/brendanryan/tempo/mpay-python/src/mpay/methods/tempo/intents.py#L288), [L310](file:///Users/brendanryan/tempo/mpay-python/src/mpay/methods/tempo/intents.py#L310)

```python
print(f"[mpay] Transaction submitted: {tx_hash}")
print(f"[mpay] Receipt found on attempt {attempt + 1}")
```

**Impact:** Library should use logging module with opt-in configuration, not stdout prints.

---

## Low Severity Issues

### 10. `realm` Parsed But Not Stored

The `Challenge` dataclass does not store `realm`, though it's required in WWW-Authenticate headers. The value is discarded during parsing and must be re-supplied when formatting.

**Impact:** `Challenge` cannot round-trip losslessly from a parsed header.

---

### 11. Receipt Not Automatically Attached by Decorator

The `@requires_payment` decorator passes `(credential, receipt)` to the handler but does not automatically set the `Payment-Receipt` header on the response. Handlers must do this manually.

**Impact:** Easy to forget to include the receipt header; not "pit of success" design.

---

### 12. Server Method Protocol Unused

The `mpay.server.method.Method` protocol is defined but appears unused—`verify_or_challenge()` takes an `Intent` directly without method routing.

---

## Conformance Checklist

| Requirement | Status | Notes |
|-------------|--------|-------|
| **Core Types** | | |
| Challenge maps to WWW-Authenticate | ✅ | Via `_parsing.py` |
| Credential maps to Authorization | ✅ | Via `_parsing.py` |
| Receipt maps to Payment-Receipt | ✅ | Via `_parsing.py` |
| **Client** | | |
| 402 transport intercepts responses | ✅ | `PaymentTransport` |
| Parses WWW-Authenticate header | ✅ | |
| Matches method to configured methods | ✅ | |
| Calls `method.create_credential()` | ✅ | |
| Retries with Authorization header | ✅ | |
| Returns final response with receipt | ⚠️ | Returns response; receipt parsing left to user |
| Handles request body replay | ❌ | Stream not buffered |
| Handles multiple challenges | ❌ | Only first Payment scheme |
| **Server** | | |
| Challenge has unique bound ID | ❌ | Random, not bound |
| Challenge includes method/intent/request | ✅ | |
| Challenge includes expires | ❌ | Never set |
| Validates credential.id binding | ❌ | Never checked |
| Validates challenge params match | ❌ | Never checked |
| Validates expires not passed | ❌ | Challenge expires not checked |
| Verifies payload per method spec | ✅ | Delegated to Intent |
| Returns Receipt on success | ✅ | |
| **Methods** | | |
| Tempo method implemented | ✅ | |
| **Intents** | | |
| Charge intent implemented | ✅ | |
| **Integrations** | | |
| httpx.AsyncClient/PaymentTransport | ✅ | |
| @requires_payment decorator | ✅ | Starlette/FastAPI + Django |

---

## Recommended Fixes (Priority Order)

1. **[CRITICAL]** Implement bound challenge IDs using HMAC of challenge parameters
2. **[CRITICAL]** Validate `credential.id` matches expected binding before verification
3. **[HIGH]** Add `expires` to challenges and validate on verification
4. **[MEDIUM]** Buffer request body for POST/PUT retry
5. **[MEDIUM]** Support multiple WWW-Authenticate challenges
6. **[MEDIUM]** Add payer identity verification using `Credential.source`
7. **[LOW]** Replace prints with logging
8. **[LOW]** Consider adding `realm` to Challenge dataclass
9. **[LOW]** Consider auto-attaching Payment-Receipt in decorator

---

## Test Coverage Gaps

Based on [tests/test_server.py](file:///Users/brendanryan/tempo/mpay-python/tests/test_server.py):

- ❌ No tests for challenge ID binding/validation
- ❌ No tests for credential replay with different request params
- ❌ No tests for challenge expiration
- ❌ No tests for POST body replay on 402
- ❌ No tests for multiple WWW-Authenticate headers

---

## Conclusion

The mpay-python SDK has a well-designed architecture that aligns with the spec's design principles (protocol-first, pluggable, minimal dependencies). However, the core security invariants of the Payment Authentication Scheme—binding between challenge parameters and credentials—are not enforced. This must be fixed before the SDK can be considered spec-conformant for production use.

**Overall Conformance Rating:** ❌ Non-Conformant (Critical issues present)
