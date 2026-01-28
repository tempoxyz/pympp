# Documentation Audit Report: mpay-python

**Audit Date:** 2026-01-28  
**Auditor:** Amp  
**Repository:** mpay-python  

---

## Executive Summary

The mpay-python documentation is generally well-structured and comprehensive. The README provides good quick-start examples and API reference. However, several issues were identified:

- **Missing example files** referenced in examples/README.md
- **Stale documentation** in README that contradicts pyproject.toml
- **Inconsistencies** between documented examples and actual code
- **Minor inaccuracies** in type signatures documented vs actual implementation

**Severity Breakdown:**

- 🔴 Critical: 1
- 🟠 High: 3  
- 🟡 Medium: 5
- 🟢 Low: 4

---

## Critical Issues

[fix -- deleted unused files] ### 1. 🔴 Missing Example Files in examples/README.md

**Location:** [examples/README.md](file:///Users/brendanryan/tempo/mpay-python/examples/README.md#L17-L20)

**Issue:** The examples/README.md references documentation files that do not exist:

- `fastapi-server.md` - **Does not exist**
- `starlette-server.md` - **Does not exist**  
- `mcp-server.md` - **Does not exist** (directory `mcp-server/` exists with README.md inside)

**Evidence:**

```markdown
| [fastapi-server.md](fastapi-server.md) | Server-side payment protection with FastAPI |
| [starlette-server.md](starlette-server.md) | Server-side payment protection with Starlette |
| [mcp-server.md](mcp-server.md) | MCP server patterns (documentation) |
```

Only these markdown files exist in examples/:

- `README.md`
- `custom-intents.md`
- `httpx-client.md`

**Fix Required:** Either create the missing files or update the README to reflect actual examples.

---

## High Severity Issues

[FIX -- just say minimal dependancies] ### 2. 🟠 README Claims "Core has no dependencies" - Incorrect

**Location:** [README.md#L10](file:///Users/brendanryan/tempo/mpay-python/README.md#L10)

**Issue:** The README states:
> **Minimal dependencies** — Core has no dependencies; extras add what you need

However, pyproject.toml shows core has a dependency:

```toml
dependencies = [
    "httpx>=0.27",
]
```

**Fix Required:** Update to: "Minimal dependencies — Core requires only httpx; extras add what you need"

---

[fix] ### 3. 🟠 Receipt Type Documentation Mismatch

**Location:** [README.md#L164-L172](file:///Users/brendanryan/tempo/mpay-python/README.md#L164-L172)

**Issue:** The README shows Receipt timestamp as a string:

```python
receipt = Receipt(
    status="success",
    timestamp="2024-01-20T12:00:00Z",  # String in docs
    reference="0x...",
)
```

But the actual implementation in `__init__.py` uses `datetime`:

```python
@dataclass(frozen=True, slots=True)
class Receipt:
    status: Literal["success", "failed"]
    timestamp: datetime  # datetime object, not string
    reference: str
```

The docstring in [\_\_init\_\_.py#L84-L91](file:///Users/brendanryan/tempo/mpay-python/src/mpay/__init__.py#L84-L91) is correct, but README is wrong.

**Fix Required:** Update README example:

```python
from datetime import datetime, UTC

receipt = Receipt(
    status="success",
    timestamp=datetime.now(UTC),
    reference="0x...",
)
```

---

[FIX] ### 4. 🟠 Server Module Docstring References Non-existent `client` Parameter

**Location:** [src/mpay/server/\_\_init\_\_.py#L9](file:///Users/brendanryan/tempo/mpay-python/src/mpay/server/__init__.py#L9)

**Issue:** The module docstring shows:

```python
intent=ChargeIntent(client),
```

But `ChargeIntent` takes `rpc_url`, not `client`:

```python
class ChargeIntent:
    def __init__(
        self,
        rpc_url: str,
        http_client: httpx.AsyncClient | None = None,
        ...
    )
```

**Fix Required:** Update docstring to:

```python
intent=ChargeIntent(rpc_url="https://rpc.tempo.xyz"),
```

---

## Medium Severity Issues

[FIX] ### 5. 🟡 Tempo Method Docstring References Non-existent `client` Parameter

**Location:** [src/mpay/methods/tempo/\_\_init\_\_.py#L18-L19](file:///Users/brendanryan/tempo/mpay-python/src/mpay/methods/tempo/__init__.py#L18-L19)

**Issue:** Same issue as #4:

```python
client = create_client(...)
intent = ChargeIntent(client)
```

`create_client` is not defined anywhere and `ChargeIntent` takes `rpc_url`.

---

[FIX -- use rpc.testnet...] ### 6. 🟡 RPC URL Inconsistency Across Examples

**Issue:** Different RPC URLs are used inconsistently:

| Location | URL |
|----------|-----|
| README.md | `https://rpc.tempo.xyz` |
| httpx-client.md | `https://rpc.testnet.tempo.xyz/` |
| fetch example | `https://rpc.testnet.tempo.xyz/` (default) |
| api-server example | `https://rpc.testnet.tempo.xyz/` (default) |
| TempoMethod default | `https://rpc.tempo.xyz` |

The README uses mainnet URL but most examples default to testnet. This could confuse users.

**Recommendation:** Be consistent - use testnet in all examples with a note that production should use mainnet.

---

[FIX] ### 7. 🟡 custom-intents.md Uses Non-existent `Receipt.success()` Parameters

**Location:** [examples/custom-intents.md#L52](file:///Users/brendanryan/tempo/mpay-python/examples/custom-intents.md#L52)

**Issue:** Example shows:

```python
return Receipt.success(reference="tx_123")
```

This is correct, but earlier in the same file (line 30-34) shows full constructor without using the convenience method:

```python
return Receipt(
    status="success",
    timestamp=datetime.now(UTC).isoformat(),  # Wrong - should be datetime object
    reference="tx_123",
)
```

The `.isoformat()` would pass a string, but Receipt expects `datetime`.

---

[FIX] ### 8. 🟡 Missing MCP Extension Documentation

**Issue:** The `mpay.extensions.mcp` module has excellent docstrings, but:

1. It's not mentioned in the main README.md
2. No top-level documentation covers the MCP integration capability
3. The `[mcp]` optional dependency is in pyproject.toml but not documented in README installation section

**Fix Required:** Add to README:

```bash
pip install mpay[mcp]            # With MCP (Model Context Protocol) support
```

---

[FIX] ### 9. 🟡 api-server README Python Version Mismatch

**Location:** [examples/api-server/README.md#L12](file:///Users/brendanryan/tempo/mpay-python/examples/api-server/README.md#L12)

**Issue:** States "Python 3.10+" but pyproject.toml requires:

```toml
requires-python = ">=3.12"
```

---

## Low Severity Issues

[FIX -- align with the readme] ### 10. 🟢 pyproject.toml Description vs README Title

**Issue:**

- pyproject.toml: `description = "HTTP 402 Payment Authentication for Python"`
- README.md title: "Python SDK for the Machine Payments Protocol (MPP)"

Minor inconsistency in naming/branding.

---

### 11. 🟢 AGENTS.md is Duplicate of README.md

**Location:** [AGENTS.md](file:///Users/brendanryan/tempo/mpay-python/AGENTS.md)

**Issue:** AGENTS.md appears to be an exact copy of README.md. While this may be intentional for agent tooling, any updates to README should be mirrored.

---

[FIX] ### 12. 🟢 ChargeIntent Print Statements

**Location:** [src/mpay/methods/tempo/intents.py#L288, L310](file:///Users/brendanryan/tempo/mpay-python/src/mpay/methods/tempo/intents.py#L288)

**Issue:** Production code contains `print()` statements:

```python
print(f"[mpay] Transaction submitted: {tx_hash}")
print(f"[mpay] Receipt found on attempt {attempt + 1}")
```

These should use logging instead. Not strictly documentation, but affects user experience.

---

### 13. 🟢 Stale Year in README Receipt Example

**Location:** [README.md#L167](file:///Users/brendanryan/tempo/mpay-python/README.md#L167)

**Issue:** Example uses `2024-01-20` which is outdated. Minor, but examples should feel current.

---

## Documentation Completeness Checklist

| Item | Status | Notes |
|------|--------|-------|
| README Quick Start - Server | ✅ | Comprehensive |
| README Quick Start - Client | ✅ | 4 patterns documented |
| API Reference - Core Types | ⚠️ | Receipt timestamp type wrong |
| API Reference - Server | ✅ | Well documented |
| API Reference - Tempo Method | ✅ | Good coverage |
| Installation Instructions | ⚠️ | Missing `[mcp]` extra |
| Development Setup | ✅ | Clear make commands |
| Examples - Runnable | ✅ | fetch/, mcp-server/, api-server/ |
| Examples - Documentation | ❌ | 3 missing files referenced |
| Docstrings - Core Types | ✅ | Excellent with examples |
| Docstrings - Server | ⚠️ | Minor param errors |
| Docstrings - Client | ✅ | Good coverage |
| Docstrings - Tempo | ⚠️ | Constructor example wrong |
| Docstrings - MCP | ✅ | Excellent |
| Type Hints | ✅ | py.typed marker present |
| License | ✅ | Dual MIT/Apache-2.0 |

---

## Recommendations

### Immediate Actions (Before Release)

1. **Fix examples/README.md** - Remove or create the 3 missing documentation files
2. **Fix Receipt timestamp examples** - Use `datetime` object, not string
3. **Fix ChargeIntent constructor examples** - Use `rpc_url=` not `client`
4. **Add `[mcp]` to installation docs**

### Near-term Improvements

1. Standardize RPC URLs across examples (use testnet consistently)
2. Replace print statements with proper logging
3. Consider generating API docs from docstrings (Sphinx/mkdocs)
4. Add a CHANGELOG.md

### Optional Enhancements

1. Add architecture diagram showing Challenge → Credential → Receipt flow
2. Add troubleshooting section for common errors
3. Document the SDK spec compliance (link to mpay-sdks/SPEC.md)

---

## SDK Spec Compliance Check

Per [mpay-sdks/SPEC.md](file:///Users/brendanryan/tempo/mpay-sdks/SPEC.md), the SDK must implement:

| Requirement | Status | Notes |
|-------------|--------|-------|
| Core types (Challenge, Credential, Receipt) | ✅ | Implemented |
| 402 Transport | ✅ | PaymentTransport |
| 402 Retry Scheme | ✅ | In transport.py |
| Challenge Generation | ✅ | verify_or_challenge creates challenges |
| Verification | ✅ | Intent.verify implemented |
| tempo method | ✅ | Full implementation |
| charge intent | ✅ | Full implementation |
| httpx integration | ✅ | AsyncClient transport |
| @requires_payment decorator | ✅ | For FastAPI/Starlette |

**Spec Compliance: PASS**

---

## Summary

The mpay-python SDK has solid documentation overall, with comprehensive docstrings and working examples. The main issues are:

1. **Broken links** in examples/README.md (3 missing files)
2. **Type inconsistencies** (Receipt timestamp documented as string, should be datetime)
3. **Stale constructor examples** (ChargeIntent(client) should be ChargeIntent(rpc_url=...))

Addressing the Critical and High severity issues should be prioritized before any release.
