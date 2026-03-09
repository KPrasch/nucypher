"""Unit tests for nucypher.utilities.rpc_proxy — eRPC integration module."""

import os
import sys
from types import SimpleNamespace
from unittest.mock import MagicMock, patch, PropertyMock

import pytest

from nucypher.utilities.rpc_proxy import (
    NUCYPHER_ENVVAR_ERPC_ENABLED,
    ERPCProcessProtocol,
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


@pytest.fixture
def mock_proxy(mock_ursula_config):
    """Create an RPCProxy with mocked erpc-py."""
    with patch.dict(sys.modules, {"erpc": _erpc_stub}):
        proxy = RPCProxy.from_ursula_config(mock_ursula_config)
    return proxy


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
        _erpc_stub.ERPCConfig.assert_called()
        _erpc_stub.CacheConfig.assert_called()


# ---------------------------------------------------------------------------
# URL rewriting
# ---------------------------------------------------------------------------


class TestRewriteEndpoints:

    def test_rewrite(self, mock_domain, sample_endpoints):
        with patch.dict(sys.modules, {"erpc": _erpc_stub}):
            config = build_erpc_config(endpoints=sample_endpoints)

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

    def test_from_config(self, mock_ursula_config, mock_domain):
        with patch.dict(sys.modules, {"erpc": _erpc_stub}):
            proxy = RPCProxy.from_config(
                eth_endpoint=mock_ursula_config.eth_endpoint,
                polygon_endpoint=mock_ursula_config.polygon_endpoint,
                condition_blockchain_endpoints=mock_ursula_config.condition_blockchain_endpoints,
                domain=mock_domain,
            )
        assert proxy.eth_endpoint == mock_ursula_config.eth_endpoint
        assert proxy.polygon_endpoint == mock_ursula_config.polygon_endpoint
        assert not proxy.is_active

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

        # Simulate erpc missing during start()
        with patch.dict(sys.modules, {"erpc.process": None, "erpc": None}):
            result = proxy.start()
            assert result is False
            assert not proxy.is_active

    def test_stop_restores_originals(self, mock_proxy):
        original_eth = mock_proxy.eth_endpoint

        # Simulate active state
        mock_proxy.eth_endpoint = "http://127.0.0.1:4000/taco-ursula/evm/1"
        mock_proxy._active = True

        mock_proxy.stop()

        assert mock_proxy.eth_endpoint == original_eth
        assert not mock_proxy.is_active

    def test_stop_idempotent(self, mock_proxy):
        """Calling stop() multiple times should not raise."""
        mock_proxy.stop()
        mock_proxy.stop()
        assert not mock_proxy.is_active

    def test_health_url_none_when_inactive(self, mock_proxy):
        assert mock_proxy.health_url is None

    def test_pid_none_when_no_process(self, mock_proxy):
        assert mock_proxy.pid is None


class TestRPCProxyStatusInfo:
    """Tests for RPCProxy.status_info() method."""

    def test_status_info_when_inactive(self, mock_proxy):
        info = mock_proxy.status_info()
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
        proxy._process_protocol = MagicMock()
        proxy._process_protocol.pid = 42
        proxy._process_protocol._restart_count = 0
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
        assert info["restarts"] == 0
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
        proxy._process_protocol = MagicMock()
        proxy._process_protocol.pid = 99
        proxy._process_protocol._restart_count = 0
        proxy.eth_endpoint = "http://127.0.0.1:4000/taco-ursula/evm/1"
        proxy.polygon_endpoint = "http://127.0.0.1:4000/taco-ursula/evm/137"
        proxy.condition_blockchain_endpoints = {1: ["http://127.0.0.1:4000/taco-ursula/evm/1"]}
        proxy.log = MagicMock()

        info = proxy.status_info()
        assert "cache_policies" in info
        assert info["cache_policies"]["eth_call"] == "0s"
        assert info["cache_policies"]["eth_getLogs"] == "2s"


# ---------------------------------------------------------------------------
# ERPCProcessProtocol lifecycle tests
# ---------------------------------------------------------------------------


class TestERPCProcessProtocol:
    """Tests for the Twisted ProcessProtocol lifecycle management."""

    def test_intentional_stop_no_restart(self, mock_proxy):
        """When stop is intentional, processEnded should not trigger restart."""
        protocol = ERPCProcessProtocol(mock_proxy)
        protocol.mark_intentional_stop()

        # Simulate processEnded with a mock reason
        mock_reason = MagicMock()
        mock_reason.value.exitCode = 0

        protocol._on_process_ended(mock_reason)

        # Should not trigger restart — proxy._fallback should NOT be called
        # because _on_stopped is called instead
        assert protocol._intentional_stop is True

    def test_unexpected_death_triggers_restart(self, mock_proxy):
        """When process dies unexpectedly, should schedule restart."""
        protocol = ERPCProcessProtocol(mock_proxy)

        mock_reason = MagicMock()
        mock_reason.value.exitCode = 1

        mock_reactor = MagicMock()
        with patch("nucypher.utilities.rpc_proxy.ERPCProcessProtocol._on_process_ended.__module__", create=True):
            with patch.dict(sys.modules, {"twisted.internet": MagicMock(), "twisted.internet.error": MagicMock()}):
                # Patch reactor.callLater within the method
                with patch("twisted.internet.reactor") as mock_reactor_mod:
                    # We need to mock the import inside the method
                    import importlib
                    with patch.dict(sys.modules):
                        mock_twisted = MagicMock()
                        mock_reactor_inner = MagicMock()
                        sys.modules["twisted"] = mock_twisted
                        sys.modules["twisted.internet"] = MagicMock()
                        sys.modules["twisted.internet.reactor"] = mock_reactor_inner
                        sys.modules["twisted.internet.error"] = MagicMock()

                        protocol._on_process_ended(mock_reason)

        assert protocol._restart_count == 1

    def test_restart_limit_triggers_fallback(self, mock_proxy):
        """After MAX_RESTARTS, should fall back to direct endpoints."""
        protocol = ERPCProcessProtocol(mock_proxy)
        protocol._restart_count = ERPCProcessProtocol.MAX_RESTARTS

        mock_reason = MagicMock()
        mock_reason.value.exitCode = 1

        with patch.dict(sys.modules, {
            "twisted": MagicMock(),
            "twisted.internet": MagicMock(),
            "twisted.internet.reactor": MagicMock(),
            "twisted.internet.error": MagicMock(),
        }):
            protocol._on_process_ended(mock_reason)

        # Should have called _fallback on the proxy
        assert not mock_proxy.is_active

    def test_reset_restart_count(self, mock_proxy):
        """reset_restart_count should zero the counter."""
        protocol = ERPCProcessProtocol(mock_proxy)
        protocol._restart_count = 2
        protocol.reset_restart_count()
        assert protocol._restart_count == 0

    def test_stderr_buffer_bounded(self, mock_proxy):
        """Stderr buffer should not grow unbounded."""
        protocol = ERPCProcessProtocol(mock_proxy)

        # Feed more than 8192 bytes of stderr
        protocol._protocol.errReceived(b"x" * 10000)

        assert len(protocol._stderr_buffer) <= 8192

    def test_exponential_backoff(self, mock_proxy):
        """Restart delays should follow exponential backoff."""
        protocol = ERPCProcessProtocol(mock_proxy)

        mock_reason = MagicMock()
        mock_reason.value.exitCode = 1

        delays = []
        original_call_later = None

        def capture_delay(delay, fn):
            delays.append(delay)

        # Patch reactor.callLater at the module level that _on_process_ended imports
        from twisted.internet import reactor
        original_call_later = reactor.callLater
        reactor.callLater = capture_delay

        try:
            # Simulate 3 consecutive deaths
            for i in range(3):
                protocol._on_process_ended(mock_reason)
        finally:
            reactor.callLater = original_call_later

        # BASE_BACKOFF=2: delays should be 2^1=2, 2^2=4, 2^3=8
        assert delays == [2, 4, 8]


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


# ---------------------------------------------------------------------------
# BlockchainInterfaceFactory proxy integration
# ---------------------------------------------------------------------------


class TestBlockchainInterfaceFactoryProxy:
    """Tests for proxy management on BlockchainInterfaceFactory."""

    @pytest.fixture(autouse=True)
    def reset_factory_proxy(self):
        from nucypher.blockchain.eth.interfaces import BlockchainInterfaceFactory
        BlockchainInterfaceFactory._proxy = None
        yield
        BlockchainInterfaceFactory._proxy = None

    def test_proxy_status_none_by_default(self):
        from nucypher.blockchain.eth.interfaces import BlockchainInterfaceFactory
        assert BlockchainInterfaceFactory.proxy_status() is None

    def test_shutdown_proxy_noop_when_none(self):
        from nucypher.blockchain.eth.interfaces import BlockchainInterfaceFactory
        BlockchainInterfaceFactory.shutdown_proxy()  # should not raise

    def test_get_proxy_endpoint_passthrough_when_no_proxy(self):
        from nucypher.blockchain.eth.interfaces import BlockchainInterfaceFactory
        assert BlockchainInterfaceFactory.get_proxy_endpoint("https://eth.example.com") == "https://eth.example.com"

    def test_configure_proxy_success(self, mock_domain):
        from nucypher.blockchain.eth.interfaces import BlockchainInterfaceFactory

        _erpc_process_stub = MagicMock()
        _erpc_process_stub.find_erpc_binary = MagicMock(return_value="/usr/local/bin/erpc")

        with patch.dict(sys.modules, {"erpc": _erpc_stub, "erpc.process": _erpc_process_stub}):
            mock_config = _erpc_stub.ERPCConfig.return_value
            mock_config.write.return_value = "/tmp/erpc-test.yaml"
            mock_config.health_url = "http://127.0.0.1:4000/"
            mock_config.endpoint_url = lambda cid: f"http://127.0.0.1:4000/taco-ursula/evm/{cid}"
            mock_config.server_port = 4000
            mock_config.metrics_port = 4001
            mock_config.upstreams = {1: ["https://eth.example.com"]}
            mock_config.cache = None

            with patch.object(RPCProxy, "_wait_for_health", return_value=True):
                with patch.object(RPCProxy, "_do_spawn", return_value=True):
                    result = BlockchainInterfaceFactory.configure_proxy(
                        eth_endpoint="https://eth.example.com",
                        polygon_endpoint="https://polygon.example.com",
                        condition_blockchain_endpoints={1: ["https://eth.example.com"]},
                        domain=mock_domain,
                    )

        assert result is True
        assert BlockchainInterfaceFactory._proxy is not None
        assert BlockchainInterfaceFactory._proxy.is_active

    def test_get_proxy_endpoint_rewrites(self, mock_domain):
        from nucypher.blockchain.eth.interfaces import BlockchainInterfaceFactory

        proxy = RPCProxy.__new__(RPCProxy)
        proxy._original_eth_endpoint = "https://eth.example.com"
        proxy._original_polygon_endpoint = "https://polygon.example.com"
        proxy._original_condition_endpoints = {42161: ["https://arb.example.com"]}
        proxy.eth_endpoint = "http://127.0.0.1:4000/taco-ursula/evm/1"
        proxy.polygon_endpoint = "http://127.0.0.1:4000/taco-ursula/evm/137"
        proxy.condition_blockchain_endpoints = {42161: ["http://127.0.0.1:4000/taco-ursula/evm/42161"]}
        proxy._active = True
        proxy.log = MagicMock()

        BlockchainInterfaceFactory._proxy = proxy

        assert BlockchainInterfaceFactory.get_proxy_endpoint("https://eth.example.com") == "http://127.0.0.1:4000/taco-ursula/evm/1"
        assert BlockchainInterfaceFactory.get_proxy_endpoint("https://polygon.example.com") == "http://127.0.0.1:4000/taco-ursula/evm/137"
        assert BlockchainInterfaceFactory.get_proxy_endpoint("https://arb.example.com") == "http://127.0.0.1:4000/taco-ursula/evm/42161"
        assert BlockchainInterfaceFactory.get_proxy_endpoint("https://unknown.example.com") == "https://unknown.example.com"

    def test_shutdown_proxy_clears(self, mock_domain):
        from nucypher.blockchain.eth.interfaces import BlockchainInterfaceFactory

        proxy = MagicMock()
        BlockchainInterfaceFactory._proxy = proxy

        BlockchainInterfaceFactory.shutdown_proxy()
        proxy.stop.assert_called_once()
        assert BlockchainInterfaceFactory._proxy is None
