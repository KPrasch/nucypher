"""Unit tests for nucypher.utilities.rpc_proxy — eRPC integration module."""

import os
import sys
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from nucypher.utilities.rpc_proxy import (
    NUCYPHER_ENVVAR_ERPC_ENABLED,
    RPCProxy,
    build_erpc_config,
    collect_endpoints,
    is_erpc_enabled,
    rewrite_endpoints,
)

# ---------------------------------------------------------------------------
# erpc stub for environments where erpc-py is not installed
# ---------------------------------------------------------------------------

_erpc_stub = MagicMock()
_erpc_stub.__name__ = "erpc"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def mock_domain():
    """Minimal domain object with eth_chain and polygon_chain."""
    return SimpleNamespace(
        eth_chain=SimpleNamespace(id=1),
        polygon_chain=SimpleNamespace(id=137),
    )


@pytest.fixture
def sample_endpoints():
    return {
        1: ["https://eth-mainnet.example.com"],
        137: ["https://polygon-mainnet.example.com"],
    }


@pytest.fixture
def mock_ursula_config(mock_domain):
    """Minimal mock of UrsulaConfiguration."""
    return SimpleNamespace(
        eth_endpoint="https://eth-mainnet.example.com",
        polygon_endpoint="https://polygon-mainnet.example.com",
        condition_blockchain_endpoints={
            1: ["https://eth-mainnet.example.com"],
            137: ["https://polygon-mainnet.example.com"],
        },
        domain=mock_domain,
    )


# ---------------------------------------------------------------------------
# Feature flag
# ---------------------------------------------------------------------------


class TestFeatureFlag:

    def test_disabled_by_default(self):
        with patch.dict(os.environ, {}, clear=True):
            os.environ.pop(NUCYPHER_ENVVAR_ERPC_ENABLED, None)
            assert is_erpc_enabled() is False

    @pytest.mark.parametrize("value", ["1", "true", "True", "TRUE", "yes", "YES"])
    def test_enabled_values(self, value):
        with patch.dict(os.environ, {NUCYPHER_ENVVAR_ERPC_ENABLED: value}):
            assert is_erpc_enabled() is True

    @pytest.mark.parametrize("value", ["0", "false", "no", "", "random"])
    def test_disabled_values(self, value):
        with patch.dict(os.environ, {NUCYPHER_ENVVAR_ERPC_ENABLED: value}):
            assert is_erpc_enabled() is False


# ---------------------------------------------------------------------------
# Endpoint collection
# ---------------------------------------------------------------------------


class TestCollectEndpoints:

    def test_basic_collection(self, mock_domain):
        result = collect_endpoints(
            eth_endpoint="https://eth.example.com",
            polygon_endpoint="https://polygon.example.com",
            condition_blockchain_endpoints={},
            domain=mock_domain,
        )
        assert 1 in result
        assert 137 in result
        assert result[1] == ["https://eth.example.com"]
        assert result[137] == ["https://polygon.example.com"]

    def test_deduplication(self, mock_domain):
        result = collect_endpoints(
            eth_endpoint="https://eth.example.com",
            polygon_endpoint="https://polygon.example.com",
            condition_blockchain_endpoints={
                1: ["https://eth.example.com", "https://eth-backup.example.com"],
            },
            domain=mock_domain,
        )
        assert result[1] == [
            "https://eth.example.com",
            "https://eth-backup.example.com",
        ]

    def test_none_endpoints(self, mock_domain):
        result = collect_endpoints(
            eth_endpoint=None,
            polygon_endpoint=None,
            condition_blockchain_endpoints={},
            domain=mock_domain,
        )
        assert result == {}

    def test_additional_chains(self, mock_domain):
        result = collect_endpoints(
            eth_endpoint="https://eth.example.com",
            polygon_endpoint=None,
            condition_blockchain_endpoints={
                42161: ["https://arbitrum.example.com"],
            },
            domain=mock_domain,
        )
        assert 42161 in result
        assert 1 in result


# ---------------------------------------------------------------------------
# Config builder (mocked erpc-py)
# ---------------------------------------------------------------------------


class TestBuildConfig:

    def test_build_config(self, sample_endpoints):
        """Verify config is built with correct parameters."""
        with patch.dict(sys.modules, {"erpc": _erpc_stub}):
            build_erpc_config(endpoints=sample_endpoints)
        # These come from erpc.ERPCConfig (mocked)
        _erpc_stub.ERPCConfig.assert_called()
        _erpc_stub.CacheConfig.assert_called()


# ---------------------------------------------------------------------------
# URL rewriting
# ---------------------------------------------------------------------------


class TestRewriteEndpoints:

    def test_rewrite(self, mock_domain, sample_endpoints):
        with patch.dict(sys.modules, {"erpc": _erpc_stub}):
            config = build_erpc_config(endpoints=sample_endpoints)

        # Configure endpoint_url to return realistic URLs
        config = _erpc_stub.ERPCConfig.return_value
        config.endpoint_url = lambda cid: f"http://127.0.0.1:4000/taco-ursula/evm/{cid}"

        new_eth, new_polygon, new_cond = rewrite_endpoints(
            config=config,
            eth_endpoint="https://eth.example.com",
            polygon_endpoint="https://polygon.example.com",
            condition_blockchain_endpoints={
                1: ["https://eth.example.com"],
                137: ["https://polygon.example.com"],
            },
            domain=mock_domain,
        )

        assert "127.0.0.1:4000" in new_eth
        assert "/evm/1" in new_eth
        assert "127.0.0.1:4000" in new_polygon
        assert "/evm/137" in new_polygon
        assert "127.0.0.1:4000" in new_cond[1][0]
        assert "127.0.0.1:4000" in new_cond[137][0]

    def test_rewrite_preserves_none(self, mock_domain, sample_endpoints):
        with patch.dict(sys.modules, {"erpc": _erpc_stub}):
            build_erpc_config(endpoints=sample_endpoints)

        config = _erpc_stub.ERPCConfig.return_value
        config.endpoint_url = lambda cid: f"http://127.0.0.1:4000/taco-ursula/evm/{cid}"

        new_eth, new_polygon, new_cond = rewrite_endpoints(
            config=config,
            eth_endpoint=None,
            polygon_endpoint="https://polygon.example.com",
            condition_blockchain_endpoints={},
            domain=mock_domain,
        )

        assert new_eth is None
        assert "127.0.0.1" in new_polygon


# ---------------------------------------------------------------------------
# RPCProxy lifecycle
# ---------------------------------------------------------------------------


class TestRPCProxy:

    def test_from_ursula_config(self, mock_ursula_config):
        with patch.dict(sys.modules, {"erpc": _erpc_stub}):
            proxy = RPCProxy.from_ursula_config(mock_ursula_config)
        assert proxy.eth_endpoint == mock_ursula_config.eth_endpoint
        assert proxy.polygon_endpoint == mock_ursula_config.polygon_endpoint
        assert not proxy.is_active

    def test_fallback_on_import_error(self, mock_ursula_config):
        """If erpc-py is not installed, start returns False."""
        with patch.dict(sys.modules, {"erpc": _erpc_stub}):
            proxy = RPCProxy.from_ursula_config(mock_ursula_config)

        # Now simulate erpc missing during start()
        with patch.dict(sys.modules, {"erpc": None}):
            result = proxy.start()
            assert result is False
            assert not proxy.is_active

    def test_stop_restores_originals(self, mock_ursula_config):
        with patch.dict(sys.modules, {"erpc": _erpc_stub}):
            proxy = RPCProxy.from_ursula_config(mock_ursula_config)
        original_eth = proxy.eth_endpoint

        # Simulate active state
        proxy.eth_endpoint = "http://127.0.0.1:4000/taco-ursula/evm/1"
        proxy._active = True

        proxy.stop()

        assert proxy.eth_endpoint == original_eth
        assert not proxy.is_active

    def test_health_url_none_when_inactive(self, mock_ursula_config):
        with patch.dict(sys.modules, {"erpc": _erpc_stub}):
            proxy = RPCProxy.from_ursula_config(mock_ursula_config)
        assert proxy.health_url is None

    def test_successful_start(self, mock_ursula_config):
        """Verify endpoints are rewritten after successful start."""
        mock_proc = MagicMock()
        mock_proc.is_running = True
        mock_proc.pid = 12345
        _erpc_stub.ERPCProcess.return_value = mock_proc

        with patch.dict(sys.modules, {"erpc": _erpc_stub}):
            proxy = RPCProxy.from_ursula_config(mock_ursula_config)
            result = proxy.start()

        assert result is True
        assert proxy.is_active
        assert "127.0.0.1" in proxy.eth_endpoint or proxy.is_active
        mock_proc.start.assert_called_once()
        mock_proc.wait_for_health.assert_called_once()


class TestRPCProxyStatusInfo:
    """Tests for RPCProxy.status_info() method."""

    def test_status_info_when_inactive(self, mock_ursula_config):
        with patch.dict(sys.modules, {"erpc": _erpc_stub}):
            proxy = RPCProxy.from_ursula_config(mock_ursula_config)
        info = proxy.status_info()
        assert info == {"active": False}

    def test_status_info_when_active(self, mock_domain, sample_endpoints):
        """Status info includes all expected fields when proxy is active."""
        mock_config = MagicMock()
        mock_config.server_port = 4000
        mock_config.metrics_port = 4001
        mock_config.health_url = "http://127.0.0.1:4000/"
        mock_config.cache = None
        mock_config.upstreams = sample_endpoints

        proxy = RPCProxy.__new__(RPCProxy)
        proxy._erpc_config = mock_config
        proxy._active = True
        proxy._process = MagicMock(pid=42)
        proxy.eth_endpoint = "http://127.0.0.1:4000/taco-ursula/evm/1"
        proxy.polygon_endpoint = "http://127.0.0.1:4000/taco-ursula/evm/137"
        proxy.condition_blockchain_endpoints = {1: ["http://127.0.0.1:4000/taco-ursula/evm/1"]}
        proxy.log = MagicMock()

        info = proxy.status_info()
        assert info["active"] is True
        assert info["pid"] == 42
        assert info["server_port"] == 4000
        assert info["metrics_port"] == 4001
        assert info["health_url"] == "http://127.0.0.1:4000/"
        assert info["upstream_count"] == 2
        assert info["chains"] == [1, 137]
        assert "cache_policies" not in info

    def test_status_info_includes_cache_policies(self, mock_domain, sample_endpoints):
        """When cache has method_ttls, status_info includes them."""
        mock_cache = SimpleNamespace(method_ttls={"eth_call": 0, "eth_getLogs": 2})
        mock_config = MagicMock()
        mock_config.server_port = 4000
        mock_config.metrics_port = 4001
        mock_config.health_url = "http://127.0.0.1:4000/"
        mock_config.cache = mock_cache
        mock_config.upstreams = sample_endpoints

        proxy = RPCProxy.__new__(RPCProxy)
        proxy._erpc_config = mock_config
        proxy._active = True
        proxy._process = MagicMock(pid=99)
        proxy.eth_endpoint = "http://127.0.0.1:4000/taco-ursula/evm/1"
        proxy.polygon_endpoint = "http://127.0.0.1:4000/taco-ursula/evm/137"
        proxy.condition_blockchain_endpoints = {1: ["http://127.0.0.1:4000/taco-ursula/evm/1"]}
        proxy.log = MagicMock()

        info = proxy.status_info()
        assert "cache_policies" in info
        assert info["cache_policies"]["eth_call"] == "0s"
        assert info["cache_policies"]["eth_getLogs"] == "2s"


class TestERPCMetricsProxyResource:
    """Tests for the Prometheus metrics proxy resource."""

    def test_renders_erpc_metrics(self):
        from nucypher.utilities.prometheus.metrics import ERPCMetricsProxyResource

        mock_proxy = MagicMock()
        mock_proxy._erpc_config.metrics_port = 4001

        resource = ERPCMetricsProxyResource(mock_proxy)
        mock_request = MagicMock()

        fake_metrics = b"# HELP erpc_requests Total requests\nerpc_requests 42\n"
        with patch("nucypher.utilities.prometheus.metrics.urlopen") as mock_urlopen:
            mock_resp = MagicMock()
            mock_resp.read.return_value = fake_metrics
            mock_resp.__enter__ = MagicMock(return_value=mock_resp)
            mock_resp.__exit__ = MagicMock(return_value=False)
            mock_urlopen.return_value = mock_resp

            result = resource.render_GET(mock_request)

        assert result == fake_metrics
        mock_request.setHeader.assert_called_once()
        mock_urlopen.assert_called_once_with("http://127.0.0.1:4001/metrics", timeout=5)

    def test_returns_503_when_erpc_unavailable(self):
        from urllib.error import URLError

        from nucypher.utilities.prometheus.metrics import ERPCMetricsProxyResource

        mock_proxy = MagicMock()
        mock_proxy._erpc_config.metrics_port = 4001

        resource = ERPCMetricsProxyResource(mock_proxy)
        mock_request = MagicMock()

        with patch("nucypher.utilities.prometheus.metrics.urlopen", side_effect=URLError("connection refused")):
            result = resource.render_GET(mock_request)

        assert result == b"eRPC metrics unavailable"
        mock_request.setResponseCode.assert_called_once_with(503)
