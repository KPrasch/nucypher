import pytest

from nucypher.blockchain.eth.utils import obfuscate_rpc_url


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
