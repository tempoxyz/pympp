---
pympp: patch
---

Fixed payment challenge request and opaque serialization to use RFC 8785 JSON Canonicalization Scheme (JCS) via the `rfc8785` library, replacing ad-hoc `json.dumps` calls across HTTP and MCP transports. This ensures challenge IDs are reproducible from the exact bytes emitted on the wire, including non-ASCII characters and JCS number formatting.
