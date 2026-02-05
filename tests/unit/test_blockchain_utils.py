import pytest

from nucypher.blockchain.eth.utils import (
    _truncate_response_text,
    obfuscate_rpc_url,
)


@pytest.mark.parametrize(
    "url,expected",
    [
        # Infura-style URLs with API key
        (
            "https://base-sepolia.infura.io/v3/25c3f47d58494214b9cbb7bdc3db99e0",
            "https://base-sepolia.infura.io/v3/25c***",
        ),
        # Alchemy-style URLs with API key
        (
            "https://eth-mainnet.alchemyapi.io/v2/abcdef1234567890abcdef1234567890",
            "https://eth-mainnet.alchemyapi.io/v2/abc***",
        ),
        # URLs without API keys should remain unchanged
        ("https://rpc.ankr.com/eth", "https://rpc.ankr.com/eth"),
        ("https://cloudflare-eth.com", "https://cloudflare-eth.com"),
        # Short path segments preserved
        ("https://example.com/v3/short", "https://example.com/v3/short"),
    ],
)
def test_obfuscate_rpc_url(url, expected):
    assert obfuscate_rpc_url(url) == expected


@pytest.mark.parametrize(
    "text,expected",
    [
        # Short text unchanged
        ("Short error", "Short error"),
        # Exactly 200 chars unchanged
        ("x" * 200, "x" * 200),
        # Long text truncated with ellipsis
        ("x" * 250, "x" * 200 + "..."),
        # Empty string unchanged
        ("", ""),
    ],
)
def test_truncate_response_text(text, expected):
    assert _truncate_response_text(text) == expected
