"""HTTP client with automatic 402 payment handling.

Example:
    from mpay.client import Client, get
    from mpay.methods.tempo import tempo

    # Simple function API
    response = await get(
        "https://api.example.com/resource",
        methods=[tempo(account=my_account, rpc_url="...")],
    )

    # Client object for connection pooling
    async with Client(methods=[tempo(...)]) as client:
        r1 = await client.get("https://api.example.com/a")
        r2 = await client.get("https://api.example.com/b")
"""

from mpay.client.transport import Client, PaymentTransport, get, post, request
