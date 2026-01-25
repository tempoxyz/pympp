# MCP Server

Payment-protected tools for MCP (Model Context Protocol) servers.

## Dependencies

```toml
[project]
dependencies = [
    "mpay[tempo]",
]
```

## Generic Integration

Works with any MCP server implementation. Extract `_meta` from params and use `verify_or_challenge()`:

```python
from mpay import Receipt
from mpay.mcp import (
    MCPChallenge,
    PaymentRequiredError,
    verify_or_challenge,
)
from mpay.methods.tempo import ChargeIntent

intent = ChargeIntent(rpc_url="https://rpc.tempo.xyz")

async def handle_tool_call(params: dict) -> dict:
    """Handler for tools/call - works with any MCP server."""
    meta = params.get("_meta")

    result = await verify_or_challenge(
        meta=meta,
        intent=intent,
        request={
            "amount": "100",
            "currency": "usd",
            "recipient": "0x742d35Cc6634C0532925a3b844Bc9e7595f8fE00",
        },
        realm="search.example.com",
        description="Web search query",
    )

    if isinstance(result, MCPChallenge):
        error = PaymentRequiredError(challenges=[result])
        return {"error": error.to_jsonrpc_error()}

    credential, receipt = result
    return {
        "result": {
            "content": [{"type": "text", "text": f"Search results (paid by {credential.source})"}],
            "_meta": receipt.to_meta(),
        }
    }
```

## FastMCP Decorator

For FastMCP and similar frameworks where tool params are unpacked as `**kwargs`:

```python
from mpay.mcp import (
    MCPCredential,
    MCPReceipt,
    PaymentRequiredError,
    requires_payment,
)
from mpay.methods.tempo import ChargeIntent

intent = ChargeIntent(rpc_url="https://rpc.tempo.xyz")

@requires_payment(
    intent=intent,
    request={
        "amount": "100",
        "currency": "usd",
        "recipient": "0x742d35Cc6634C0532925a3b844Bc9e7595f8fE00",
    },
    realm="search.example.com",
    description="Web search query",
)
async def web_search(
    query: str,
    *,
    credential: MCPCredential,
    receipt: MCPReceipt,
) -> str:
    return f"Search results for '{query}' (paid by {credential.source})"


# Usage in MCP server
async def handle_web_search(params: dict):
    try:
        result = await web_search(**params.get("arguments", {}), _meta=params.get("_meta"))
        return {"result": {"content": [{"type": "text", "text": result}]}}
    except PaymentRequiredError as e:
        return {"error": e.to_jsonrpc_error()}
```

## Error Handling

MCP uses JSON-RPC error codes for payment errors:

```python
from mpay.mcp import (
    create_challenge,
    PaymentRequiredError,
    PaymentVerificationError,
)

challenge = create_challenge(
    method="tempo",
    intent_name="charge",
    request={"amount": "100", "currency": "usd"},
    realm="api.example.com",
    description="API call",
)

# Payment required (-32042)
error1 = PaymentRequiredError(challenges=[challenge])
print(error1.to_jsonrpc_error())
# {"code": -32042, "message": "Payment required", "data": {"challenges": [...]}}

# Verification failed (-32043)
error2 = PaymentVerificationError(
    challenges=[challenge],
    reason="signature-invalid",
    detail="Signature verification failed",
)
print(error2.to_jsonrpc_error())
# {"code": -32043, "message": "Payment verification failed", "data": {...}}
```

## Complete Example

```python
import asyncio
from mpay.mcp import (
    MCPChallenge,
    MCPCredential,
    PaymentRequiredError,
    verify_or_challenge,
)
from mpay.methods.tempo import ChargeIntent

intent = ChargeIntent(rpc_url="https://rpc.tempo.xyz")

async def handle_tool_call(params: dict) -> dict:
    result = await verify_or_challenge(
        meta=params.get("_meta"),
        intent=intent,
        request={"amount": "100", "currency": "usd", "recipient": "0x..."},
        realm="api.example.com",
        description="Tool call",
    )

    if isinstance(result, MCPChallenge):
        return {"error": PaymentRequiredError(challenges=[result]).to_jsonrpc_error()}

    credential, receipt = result
    return {
        "result": {
            "content": [{"type": "text", "text": "Tool result"}],
            "_meta": receipt.to_meta(),
        }
    }

async def main():
    # Step 1: Call without credential
    response = await handle_tool_call({"name": "tool", "arguments": {}})
    print("Without credential:", response)

    # Step 2: Parse challenge and create credential
    challenge_data = response["error"]["data"]["challenges"][0]
    challenge = MCPChallenge.from_dict(challenge_data)
    credential = MCPCredential(
        challenge=challenge,
        payload={"signature": "0x..."},
        source="0x...",
    )

    # Step 3: Retry with credential
    response = await handle_tool_call({
        "name": "tool",
        "arguments": {},
        "_meta": credential.to_meta(),
    })
    print("With credential:", response)

if __name__ == "__main__":
    asyncio.run(main())
```
