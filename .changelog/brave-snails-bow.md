---
pympp: patch
---

Fixed a security issue where a non-address recipient value in a Tempo charge could spill into the transfer calldata's amount word, causing amount caps to be bypassed (VERIA-1145). Added `_check_recipient_addresses` validation that rejects malformed primary and split recipients before signing, and extracted `_abi_address` and `_abi_uint256` helpers with explicit bounds checks for ABI encoding.
