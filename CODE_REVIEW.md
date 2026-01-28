# mpay-python SDK Code Review

**Date:** 2026-01-28  
**Reviewer:** Amp AI  
**SDK Version:** 0.1.0  
**Repository:** ~/tempo/mpay-python

## Executive Summary

The mpay-python SDK is well-structured and implements the Payment HTTP Authentication Scheme with clean, readable code. The codebase passes all linting checks and has comprehensive test coverage (104 passing tests). However, there are **3 high-severity security issues** and several code quality improvements that should be addressed before production use.

### Risk Summary

| Severity | Count | Description |
|----------|-------|-------------|
| 🔴 High | 3 | Challenge replay, payer identity not verified, SSRF potential |
| 🟠 Medium | 5 | Print statements, exception handling gaps, dead code |
| 🟡 Low | 12 | Type consistency, code duplication, API ergonomics |

---

## 1. Security Issues

[FIX -- make this work like js] ### 🔴 HIGH: Challenge Not Bound to Request/Expiry (Replay Vulnerability)

**Files:** [`src/mpay/server/verify.py#L79-L90`](file:///Users/brendanryan/tempo/mpay-python/src/mpay/server/verify.py#L79-L90), [`src/mpay/extensions/mcp/verify.py`](file:///Users/brendanryan/tempo/mpay-python/src/mpay/extensions/mcp/verify.py)

**Issue:** Challenges are created with a random ID but:

- Not stored server-side
- Not cryptographically signed
- Not bound to the specific request parameters
- `expires` field exists on `Challenge` but is never set or validated

**Impact:** Attackers can replay credentials across different requests or forge credentials with modified challenge data.

**Recommendation:**

```python
# Stateless signed challenge approach
import hmac
import hashlib

def _create_challenge(..., secret: bytes) -> Challenge:
    id = secrets.token_urlsafe(16)
    expires = (datetime.now(UTC) + timedelta(minutes=5)).isoformat()
    
    # Create digest binding challenge to request
    canonical = json.dumps({
        "id": id, "realm": realm, "method": method,
        "intent": intent_name, "request": request, "expires": expires
    }, sort_keys=True)
    digest = hmac.new(secret, canonical.encode(), hashlib.sha256).hexdigest()
    
    return Challenge(
        id=id, method=method, intent=intent_name,
        request=request, expires=expires, digest=f"sha-256=:{digest}:"
    )
```

---

[fix -- make this align with mpay] ### 🔴 HIGH: Payer Identity Not Verified (Tempo Method)

**File:** [`src/mpay/methods/tempo/intents.py#L192-L234`](file:///Users/brendanryan/tempo/mpay-python/src/mpay/methods/tempo/intents.py#L192-L234)

**Issue:** `_verify_transfer_logs()` accepts an `expected_sender` parameter but it is **never passed by callers**:

- Line 185: `self._verify_transfer_logs(receipt_data, request)` (no sender)
- Line 323: `self._verify_transfer_logs(receipt_data, request)` (no sender)

**Impact:** Any transaction with matching amount/currency/recipient passes verification, regardless of who paid. An attacker could reuse someone else's transaction hash to unlock paid content.

**Recommendation:**

```python
# In _verify_hash, extract sender from Credential.source and validate
async def _verify_hash(self, payload: HashCredentialPayload, request: ChargeRequest) -> Receipt:
    # ... existing code ...
    
    # Derive expected sender from credential source DID
    expected_sender = None
    if credential.source and credential.source.startswith("did:pkh:eip155:"):
        expected_sender = credential.source.split(":")[-1]
    
    if not self._verify_transfer_logs(receipt_data, request, expected_sender):
        raise VerificationError("...")
```

---

### 🔴 HIGH: SSRF via User-Controlled Fee Payer URL

**Files:** [`src/mpay/methods/tempo/schemas.py#L15`](file:///Users/brendanryan/tempo/mpay-python/src/mpay/methods/tempo/schemas.py#L15), [`src/mpay/methods/tempo/intents.py#L249-L259`](file:///Users/brendanryan/tempo/mpay-python/src/mpay/methods/tempo/intents.py#L249-L259)

[FIX] **Issue:** `ChargeRequest.methodDetails.feePayerUrl` is used directly in an HTTP POST without validation. If developers build `request` from user input (as suggested in docs), this becomes an SSRF attack vector.

**Recommendation:**

```python
# Add URL validation in ChargeRequest schema
class MethodDetails(BaseModel):
    feePayerUrl: str | None = None
    
    @field_validator("feePayerUrl")
    @classmethod
    def validate_fee_payer_url(cls, v: str | None) -> str | None:
        if v is None:
            return v
        parsed = urlparse(v)
        if parsed.scheme != "https":
            raise ValueError("feePayerUrl must use HTTPS")
        # Consider adding domain allowlist
        return v
```

---

## 2. Code Quality Issues

[fix] ### 🟠 MEDIUM: Print Statements Instead of Logging

**File:** [`src/mpay/methods/tempo/intents.py#L288`](file:///Users/brendanryan/tempo/mpay-python/src/mpay/methods/tempo/intents.py#L288), [`#L310`](file:///Users/brendanryan/tempo/mpay-python/src/mpay/methods/tempo/intents.py#L310)

```python
print(f"[mpay] Transaction submitted: {tx_hash}")
print(f"[mpay] Receipt found on attempt {attempt + 1}")
```

**Issue:** SDK should never use `print()`. This pollutes stdout and cannot be controlled by users.

**Recommendation:**

```python
import logging
logger = logging.getLogger(__name__)

logger.debug("Transaction submitted: %s", tx_hash)
logger.debug("Receipt found on attempt %d", attempt + 1)
```

---

[fix] ### 🟠 MEDIUM: Exception Handling Gap in Base64 Decode

**File:** [`src/mpay/_parsing.py#L62-L63`](file:///Users/brendanryan/tempo/mpay-python/src/mpay/_parsing.py#L62-L63)

```python
except (ValueError, json.JSONDecodeError):
    raise ParseError("Invalid base64 or JSON encoding") from None
```

**Issue:** `json.loads()` on bytes can raise `UnicodeDecodeError` which is not caught. While `binascii.Error` is a subclass of `ValueError` (covered), malformed UTF-8 will propagate as an unexpected exception.

**Recommendation:**

```python
except (ValueError, json.JSONDecodeError, UnicodeDecodeError):
    raise ParseError("Invalid base64 or JSON encoding") from None
```

---

[fix]### 🟠 MEDIUM: Assert Used for Runtime Validation

**File:** [`src/mpay/methods/tempo/keychain.py#L41`](file:///Users/brendanryan/tempo/mpay-python/src/mpay/methods/tempo/keychain.py#L41)

```python
assert len(keychain_sig) == KEYCHAIN_SIGNATURE_LENGTH
```

**Issue:** `assert` statements are removed when Python runs with `-O` optimization flag.

**Recommendation:**

```python
if len(keychain_sig) != KEYCHAIN_SIGNATURE_LENGTH:
    raise ValueError(f"Invalid keychain signature length: {len(keychain_sig)}")
```

---

### 🟠 MEDIUM: VerificationError Not Caught in HTTP Flow

**File:** [`src/mpay/server/verify.py#L75-L76`](file:///Users/brendanryan/tempo/mpay-python/src/mpay/server/verify.py#L75-L76)

**Issue:** `intent.verify()` can raise `VerificationError`, but this is not caught. In the HTTP decorator flow, this will become a 500 error instead of returning a 402 challenge.

**Recommendation:** Either catch and convert to a challenge, or document that `VerificationError` must be handled by the framework.

---

[fix -- this should use the chain id for the given intent] ### 🟠 MEDIUM: Hardcoded Chain ID in DID

**File:** [`src/mpay/methods/tempo/client.py#L102`](file:///Users/brendanryan/tempo/mpay-python/src/mpay/methods/tempo/client.py#L102)

```python
source=f"did:pkh:eip155:1:{self.account.address}"
```

**Issue:** Chain ID is hardcoded to `1` (Ethereum mainnet) regardless of the actual Tempo chain being used. Tempo mainnet uses chain ID `42431`.

**Recommendation:** Use the chain ID fetched from RPC:

```python
source=f"did:pkh:eip155:{chain_id}:{self.account.address}"
```

---

## 3. Dead/Unnecessary Code

[fix] ### 🟡 Unused Constant (Dead Code)

**File:** [`src/mpay/methods/tempo/client.py#L18`](file:///Users/brendanryan/tempo/mpay-python/src/mpay/methods/tempo/client.py#L18)

```python
DEFAULT_FEE_PAYER_URL = "https://sponsor.moderato.tempo.xyz"
```

This constant is defined but never used in `client.py`. It's duplicated and used in `intents.py`.

**Recommendation:** Remove from `client.py`.

---

[fix] ### 🟡 Realm Parameter Unused

**File:** [`src/mpay/server/verify.py#L20`](file:///Users/brendanryan/tempo/mpay-python/src/mpay/server/verify.py#L20)

The `realm` parameter is passed to `verify_or_challenge()` but never used in the function body.

**Recommendation:** Either use it to bind challenges (recommended for security) or remove it from the signature.

---

[fix] ### 🟡 Duplicated Verification Logic

**Files:**

- [`src/mpay/extensions/mcp/decorator.py#L117-L175`](file:///Users/brendanryan/tempo/mpay-python/src/mpay/extensions/mcp/decorator.py#L117-L175)
- [`src/mpay/extensions/mcp/verify.py#L55-L163`](file:///Users/brendanryan/tempo/mpay-python/src/mpay/extensions/mcp/verify.py#L55-L163)

**Issue:** The MCP decorator duplicates the verification logic from `verify.py` instead of delegating to it.

**Recommendation:** Refactor decorator to use `verify_or_challenge()` internally.

---

## 4. Design & API Issues

[fix -- make a datetime] ### 🟡 Type Inconsistency: expires as String vs datetime

**Files:**

- [`src/mpay/__init__.py#L41`](file:///Users/brendanryan/tempo/mpay-python/src/mpay/__init__.py#L41): `Challenge.expires: str | None`
- [`src/mpay/__init__.py#L94`](file:///Users/brendanryan/tempo/mpay-python/src/mpay/__init__.py#L94): `Receipt.timestamp: datetime`

**Recommendation:** For consistency, either make `expires` a `datetime` or clearly document it's a raw ISO 8601 string.

---

### 🟡 Two Incompatible Method Protocols

**Files:**

- [`src/mpay/client/transport.py#L23-L31`](file:///Users/brendanryan/tempo/mpay-python/src/mpay/client/transport.py#L23-L31): `Method` with `name` + `create_credential()`
- [`src/mpay/server/method.py#L12-L47`](file:///Users/brendanryan/tempo/mpay-python/src/mpay/server/method.py#L12-L47): `Method` with `name` + `intents` + `create_credential()`

**Recommendation:** Define a shared protocol or rename to `ClientMethod`/`ServerMethod`.

---

### 🟡 Transport Retry May Fail with Streaming Bodies

**File:** [`src/mpay/client/transport.py#L89-L97`](file:///Users/brendanryan/tempo/mpay-python/src/mpay/client/transport.py#L89-L97)

```python
retry_request = httpx.Request(
    method=request.method,
    url=request.url,
    headers=headers,
    stream=request.stream,  # Single-use stream!
    extensions=request.extensions,
)
```

**Issue:** httpx request streams are often single-use. If the original request body was streamed, the retry will fail or send empty body.

**Recommendation:**

- Document that streaming bodies are not supported with automatic payment handling
- Or read the body into memory before retry

---

### 🟡 MCP Hard Dependency Not Optional

**File:** [`src/mpay/extensions/mcp/errors.py#L15-L16`](file:///Users/brendanryan/tempo/mpay-python/src/mpay/extensions/mcp/errors.py#L15-L16)

```python
from mcp.shared.exceptions import McpError
from mcp.types import ErrorData
```

**Issue:** Importing `mpay.extensions.mcp` fails if `mcp` package is not installed, even though it's listed as an optional dependency.

**Recommendation:** Use lazy imports:

```python
def _get_mcp_deps():
    try:
        from mcp.shared.exceptions import McpError
        from mcp.types import ErrorData
        return McpError, ErrorData
    except ImportError:
        raise ImportError("Install mpay[mcp] for MCP support") from None
```

---

[fix] ### 🟡 Address Regex Too Permissive

**File:** [`src/mpay/methods/tempo/schemas.py#L25-L26`](file:///Users/brendanryan/tempo/mpay-python/src/mpay/methods/tempo/schemas.py#L25-L26)

```python
currency: Annotated[str, Field(pattern=r"^0x[a-fA-F0-9]+$")]
recipient: Annotated[str, Field(pattern=r"^0x[a-fA-F0-9]+$")]
```

**Issue:** Accepts any length hex string. EVM addresses are exactly 40 hex characters.

**Recommendation:**

```python
pattern=r"^0x[a-fA-F0-9]{40}$"
```

---

[fix] ### 🟡 No Validation of root_account in Keychain

**File:** [`src/mpay/methods/tempo/keychain.py#L38-L39`](file:///Users/brendanryan/tempo/mpay-python/src/mpay/methods/tempo/keychain.py#L38-L39)

```python
root_bytes = bytes.fromhex(root_account[2:])
```

**Issue:** No validation that `root_account` is a valid 42-character 0x-prefixed address. Will throw cryptic errors on invalid input.

**Recommendation:**

```python
if not root_account.startswith("0x") or len(root_account) != 42:
    raise ValueError(f"Invalid root account address: {root_account}")
root_bytes = bytes.fromhex(root_account[2:])
```

---

### 🟡 Signature Munging in Decorator Breaks Introspection

**File:** [`src/mpay/server/decorator.py#L129-L130`](file:///Users/brendanryan/tempo/mpay-python/src/mpay/server/decorator.py#L129-L130)

```python
wrapper.__signature__ = new_sig
del wrapper.__wrapped__
```

**Issue:** Deleting `__wrapped__` breaks introspection tools, framework features (dependency injection, OpenAPI generation), and debugging.

**Recommendation:** Keep `__wrapped__` or provide alternative metadata for framework integration.

---

### 🟡 Error Messages May Leak RPC Internals

**File:** [`src/mpay/methods/tempo/intents.py#L274-L282`](file:///Users/brendanryan/tempo/mpay-python/src/mpay/methods/tempo/intents.py#L274-L282)

```python
raise VerificationError(f"Transaction submission failed: {full_error}")
```

**Issue:** `error_data` from RPC nodes may contain debug traces, request echoes, or sensitive information.

**Recommendation:** Sanitize error messages or only include RPC details in debug logs.

---

## 5. Positive Observations

✅ **Clean Architecture:** Protocol-first design with clear separation of concerns  
✅ **Good Type Hints:** Comprehensive use of modern Python typing (3.12+)  
✅ **Immutable Types:** Core types use `frozen=True, slots=True` dataclasses  
✅ **Comprehensive Tests:** 104 passing tests with good coverage  
✅ **Consistent Code Style:** Passes ruff linting with no warnings  
✅ **Good Documentation:** AGENTS.md and docstrings are thorough  
✅ **Async Native:** Proper use of async/await patterns  

---

## Recommended Action Items

### Priority 1 (Security - Fix Before Production)

1. Implement challenge binding with HMAC digest and expiry validation
2. Verify payer identity in Tempo intent by passing `expected_sender`
3. Add URL validation/allowlist for `feePayerUrl`

### Priority 2 (Quality - Fix Soon)

1. Replace `print()` with `logging`
2. Add `UnicodeDecodeError` to parsing exception handling
3. Replace `assert` with explicit validation in keychain.py
4. Remove dead `DEFAULT_FEE_PAYER_URL` constant from client.py

### Priority 3 (Improvements)

1. Fix hardcoded chain ID in DID construction
2. Tighten address regex patterns to 40 hex chars
3. Document streaming body limitation in transport
4. Make MCP imports optional/lazy
5. Unify Method protocols or rename to avoid confusion

---

## Estimated Effort

| Priority | Items | Effort |
|----------|-------|--------|
| P1 Security | 3 | 1-2 days |
| P2 Quality | 4 | 2-4 hours |
| P3 Improvements | 5 | 4-8 hours |

**Total:** 2-3 days for comprehensive fixes
