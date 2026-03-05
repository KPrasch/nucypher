import os
from typing import Any, Dict, List, Optional

from nucypher.config.constants import NUCYPHER_ENVVAR_ERPC_ENABLED
from nucypher.utilities.logging import Logger

_TRUE_VALUES = {"1", "true", "yes"}

logger = Logger("eRPC")


def is_erpc_enabled() -> bool:
    """Check whether the eRPC proxy feature is enabled via environment."""
    return os.environ.get(NUCYPHER_ENVVAR_ERPC_ENABLED, "").lower() in _TRUE_VALUES


# Cache TTL policy: DKG-critical calls (eth_call) must never be cached.
# Finalized/immutable data can be cached aggressively.
_TACO_CACHE_TTLS = {
    "eth_call": 0,
    "eth_sendRawTransaction": 0,
    "eth_getLogs": 2,
    "eth_blockNumber": 4,
    "eth_gasPrice": 12,
    "eth_getBalance": 4,
    "eth_getTransactionCount": 4,
    "eth_getBlockByNumber": 300,
    "eth_getBlockByHash": 3600,
    "eth_getTransactionReceipt": 3600,
    "eth_chainId": 86400,
}


def build_erpc_config(
    endpoints: Dict[int, List[str]],
    project_id: str = "taco-ursula",
    server_port: int = 4000,
    metrics_port: int = 4001,
    log_level: str = "info",
    cache_max_items: int = 10_000,
):
    """Build an ERPCConfig from Ursula's chain endpoints.

    Parameters
    ----------
    endpoints :
        Mapping of chain_id → list of RPC URLs, exactly as stored in
        ``UrsulaConfiguration.condition_blockchain_endpoints`` (plus
        ``eth_endpoint`` / ``polygon_endpoint``).
    project_id :
        eRPC project identifier (appears in proxy URLs).
    server_port :
        Local port for the eRPC HTTP proxy.
    metrics_port :
        Local port for the eRPC metrics endpoint.
    log_level :
        eRPC log verbosity (trace/debug/info/warn/error).
    cache_max_items :
        Maximum in-memory cache entries.

    Returns
    -------
    erpc.ERPCConfig
        Fully configured eRPC config ready to start a process.

    Raises
    ------
    ImportError
        If ``erpc-py`` is not installed.
    """
    from erpc import CacheConfig, ERPCConfig

    cache = CacheConfig(
        max_items=cache_max_items,
        method_ttls=dict(_TACO_CACHE_TTLS),
    )

    config = ERPCConfig(
        project_id=project_id,
        upstreams=dict(endpoints),
        server_host="127.0.0.1",
        server_port=server_port,
        metrics_host="127.0.0.1",
        metrics_port=metrics_port,
        log_level=log_level,
        cache=cache,
    )

    return config


def collect_endpoints(
    eth_endpoint: Optional[str],
    polygon_endpoint: Optional[str],
    condition_blockchain_endpoints: Optional[Dict[int, List[str]]],
    domain,
) -> Dict[int, List[str]]:
    """Collect all chain endpoints from Ursula's configuration into a unified map.

    Mirrors the logic in ``UrsulaConfiguration.configure_condition_blockchain_endpoints``
    without modifying any config state.

    Parameters
    ----------
    eth_endpoint :
        Primary Ethereum RPC URL.
    polygon_endpoint :
        Primary Polygon RPC URL.
    condition_blockchain_endpoints :
        Additional per-chain endpoints from config.
    domain :
        The TACo domain (provides ``eth_chain.id`` and ``polygon_chain.id``).

    Returns
    -------
    dict
        chain_id → [url, ...] mapping.
    """
    endpoints: Dict[int, List[str]] = {}

    if condition_blockchain_endpoints:
        for chain_id, urls in condition_blockchain_endpoints.items():
            chain_id = int(chain_id)
            if isinstance(urls, str):
                urls = [urls]
            endpoints[chain_id] = list(urls)

    if eth_endpoint:
        eth_chain_id = domain.eth_chain.id
        chain_urls = endpoints.setdefault(eth_chain_id, [])
        if eth_endpoint not in chain_urls:
            chain_urls.append(eth_endpoint)

    if polygon_endpoint:
        polygon_chain_id = domain.polygon_chain.id
        chain_urls = endpoints.setdefault(polygon_chain_id, [])
        if polygon_endpoint not in chain_urls:
            chain_urls.append(polygon_endpoint)

    return endpoints


def rewrite_endpoints(
    config,
    eth_endpoint: Optional[str],
    polygon_endpoint: Optional[str],
    condition_blockchain_endpoints: Dict[int, List[str]],
    domain,
) -> tuple[Optional[str], Optional[str], Dict[int, List[str]]]:
    """Rewrite provider URLs to route through the local eRPC proxy.

    Returns new (eth_endpoint, polygon_endpoint, condition_blockchain_endpoints)
    with URLs pointed at ``http://127.0.0.1:<port>/<project>/evm/<chain_id>``.
    The original values are NOT modified.
    """
    eth_chain_id = domain.eth_chain.id
    polygon_chain_id = domain.polygon_chain.id

    new_eth = config.endpoint_url(eth_chain_id) if eth_endpoint else eth_endpoint
    new_polygon = (
        config.endpoint_url(polygon_chain_id) if polygon_endpoint else polygon_endpoint
    )

    new_condition_endpoints = {}
    for chain_id, urls in condition_blockchain_endpoints.items():
        if urls:
            new_condition_endpoints[chain_id] = [config.endpoint_url(int(chain_id))]

    return new_eth, new_polygon, new_condition_endpoints


class RPCProxyHealthCheck:
    """Twisted LoopingCall health monitor for the eRPC proxy.

    Periodically checks process liveness and scrapes eRPC Prometheus
    metrics to surface request counts, error rates, and cache stats
    directly in Ursula's log stream.
    """

    INTERVAL = 60  # seconds

    def __init__(self, rpc_proxy: "RPCProxy"):
        from twisted.internet import reactor
        from twisted.internet.task import LoopingCall

        self._proxy = rpc_proxy
        self.log = Logger("eRPC")
        self._task = LoopingCall(self.run)
        self._task.clock = reactor
        self._last_request_count = 0
        self._check_count = 0

    @property
    def running(self) -> bool:
        return self._task.running

    def start(self) -> None:
        if not self.running:
            d = self._task.start(interval=self.INTERVAL, now=False)
            d.addErrback(self._handle_error)

    def stop(self) -> None:
        if self.running:
            self._task.stop()

    def run(self) -> None:
        self._check_count += 1
        if not (self._proxy._process and self._proxy._process.is_running):
            self.log.warn("eRPC proxy process is not running")
            return

        # Scrape lightweight stats from eRPC Prometheus metrics
        stats = self._scrape_stats()
        if stats:
            total_reqs = stats.get("total_requests", 0)
            delta = total_reqs - self._last_request_count
            self._last_request_count = total_reqs

            # Log a periodic summary (every 5 checks = ~5 min)
            if self._check_count % 5 == 0 or delta > 0:
                cache_hits = stats.get("cache_hits", 0)
                cache_misses = stats.get("cache_misses", 0)
                errors = stats.get("errors", 0)
                self.log.info(
                    "eRPC proxy: {delta} reqs (total: {total}), "
                    "cache {hits}/{misses} hit/miss, {errors} errors, "
                    "PID {pid}",
                    delta=delta,
                    total=total_reqs,
                    hits=cache_hits,
                    misses=cache_misses,
                    errors=errors,
                    pid=self._proxy._process.pid,
                )
        else:
            self.log.debug(
                "eRPC proxy alive (PID {pid})",
                pid=self._proxy._process.pid,
            )

    def _scrape_stats(self) -> Optional[Dict[str, int]]:
        """Scrape key counters from eRPC's Prometheus metrics endpoint."""
        import urllib.request

        metrics_url = (
            f"http://127.0.0.1:{self._proxy._erpc_config.metrics_port}/metrics"
        )
        try:
            with urllib.request.urlopen(metrics_url, timeout=2) as resp:
                body = resp.read().decode()
        except Exception:
            return None

        stats: Dict[str, int] = {}
        for line in body.splitlines():
            if line.startswith("#"):
                continue
            # Total requests proxied
            if "erpc_requests_received_total" in line and "{" not in line:
                stats["total_requests"] = int(float(line.split()[-1]))
            # Aggregate cache hits/misses
            elif "erpc_cache_hits_total" in line and "{" not in line:
                stats["cache_hits"] = int(float(line.split()[-1]))
            elif "erpc_cache_misses_total" in line and "{" not in line:
                stats["cache_misses"] = int(float(line.split()[-1]))
            # Errors
            elif "erpc_errors_total" in line and "{" not in line:
                stats["errors"] = int(float(line.split()[-1]))
        return stats if stats else None

    def _handle_error(self, failure) -> None:
        self.log.warn("eRPC health check error: {error}", error=repr(failure))


class RPCProxy:
    """Manages the eRPC proxy process alongside Ursula.

    Designed to be instantiated during Ursula startup and stopped during
    shutdown.  If the proxy fails to start, falls back silently to direct
    RPC endpoints (no crash, no disruption).
    """

    def __init__(
        self,
        erpc_config,
        original_eth_endpoint: str,
        original_polygon_endpoint: str,
        original_condition_endpoints: Dict[int, List[str]],
        domain,
    ):
        self.log = Logger(self.__class__.__name__)
        self._erpc_config = erpc_config
        self._domain = domain

        # Originals — preserved for fallback
        self._original_eth_endpoint = original_eth_endpoint
        self._original_polygon_endpoint = original_polygon_endpoint
        self._original_condition_endpoints = dict(original_condition_endpoints)

        # Active endpoints — start as originals, rewritten on successful start
        self.eth_endpoint = original_eth_endpoint
        self.polygon_endpoint = original_polygon_endpoint
        self.condition_blockchain_endpoints = dict(original_condition_endpoints)

        self._process = None
        self._active = False
        self._health_check = None

    @classmethod
    def from_config(
        cls,
        eth_endpoint: str,
        polygon_endpoint: str,
        condition_blockchain_endpoints: Dict[int, List[str]],
        domain,
    ) -> "RPCProxy":
        """Create an RPCProxy from raw endpoint values (no character dependency)."""
        endpoints = collect_endpoints(
            eth_endpoint=eth_endpoint,
            polygon_endpoint=polygon_endpoint,
            condition_blockchain_endpoints=condition_blockchain_endpoints,
            domain=domain,
        )

        try:
            erpc_config = build_erpc_config(endpoints=endpoints)
        except ImportError:
            logger.warn("erpc-py is not installed — cannot build eRPC config")
            raise

        return cls(
            erpc_config=erpc_config,
            original_eth_endpoint=eth_endpoint,
            original_polygon_endpoint=polygon_endpoint,
            original_condition_endpoints=condition_blockchain_endpoints or {},
            domain=domain,
        )

    @classmethod
    def from_ursula_config(cls, config) -> "RPCProxy":
        """Create an RPCProxy from an UrsulaConfiguration instance."""
        endpoints = collect_endpoints(
            eth_endpoint=config.eth_endpoint,
            polygon_endpoint=config.polygon_endpoint,
            condition_blockchain_endpoints=config.condition_blockchain_endpoints,
            domain=config.domain,
        )

        try:
            erpc_config = build_erpc_config(endpoints=endpoints)
        except ImportError:
            logger.warn("erpc-py is not installed — cannot build eRPC config")
            raise

        return cls(
            erpc_config=erpc_config,
            original_eth_endpoint=config.eth_endpoint,
            original_polygon_endpoint=config.polygon_endpoint,
            original_condition_endpoints=config.condition_blockchain_endpoints,
            domain=config.domain,
        )

    @classmethod
    def from_ursula(cls, ursula) -> "RPCProxy":
        """Create an RPCProxy from a live Ursula instance."""
        endpoints = collect_endpoints(
            eth_endpoint=ursula.eth_endpoint,
            polygon_endpoint=ursula.polygon_endpoint,
            condition_blockchain_endpoints=ursula.condition_blockchain_endpoints,
            domain=ursula.domain,
        )

        try:
            erpc_config = build_erpc_config(endpoints=endpoints)
        except ImportError:
            logger.warn("erpc-py is not installed — cannot build eRPC config")
            raise

        return cls(
            erpc_config=erpc_config,
            original_eth_endpoint=ursula.eth_endpoint,
            original_polygon_endpoint=ursula.polygon_endpoint,
            original_condition_endpoints=ursula.condition_blockchain_endpoints or {},
            domain=ursula.domain,
        )

    @property
    def is_active(self) -> bool:
        """Whether the eRPC proxy is running and endpoints are rewritten."""
        return self._active

    def start(self, health_timeout: int = 30) -> bool:
        """Start the eRPC proxy process.

        Returns ``True`` if the proxy started successfully, ``False`` on
        fallback to direct endpoints.
        """
        try:
            from erpc import ERPCProcess
        except ImportError:
            self.log.warn("erpc-py is not installed — running without RPC proxy")
            return False

        try:
            self._process = ERPCProcess(config=self._erpc_config)
            self._process.start()
            self._process.wait_for_health(timeout=health_timeout)
        except Exception as e:
            stderr = ""
            if self._process and hasattr(self._process, '_process'):
                inner = self._process._process
                if inner and inner.stderr:
                    try:
                        stderr = inner.stderr.read().decode(errors="replace")
                    except Exception:
                        pass
            msg = f"eRPC proxy failed to start — falling back to direct endpoints: {repr(e)}"
            if stderr:
                msg += f"\neRPC stderr: {stderr[:500]}"
            self.log.warn(msg)
            self._fallback()
            return False

        (
            self.eth_endpoint,
            self.polygon_endpoint,
            self.condition_blockchain_endpoints,
        ) = rewrite_endpoints(
            config=self._erpc_config,
            eth_endpoint=self._original_eth_endpoint,
            polygon_endpoint=self._original_polygon_endpoint,
            condition_blockchain_endpoints=self._original_condition_endpoints,
            domain=self._domain,
        )

        self._active = True
        self.log.info(f"eRPC proxy started (PID {self._process.pid})")

        # Start periodic health monitoring
        try:
            self._health_check = RPCProxyHealthCheck(self)
            self._health_check.start()
        except Exception:
            pass  # Health check is best-effort, don't fail startup

        return True

    def stop(self) -> None:
        """Stop the eRPC proxy and restore original endpoints."""
        if self._health_check and self._health_check.running:
            self._health_check.stop()
        if self._process and self._process.is_running:
            try:
                self._process.stop()
                self.log.info("eRPC proxy stopped")
            except Exception as e:
                self.log.warn(f"Error stopping eRPC proxy: {repr(e)}")
        self._fallback()

    def _fallback(self) -> None:
        """Restore original endpoints (direct RPC, no proxy)."""
        self.eth_endpoint = self._original_eth_endpoint
        self.polygon_endpoint = self._original_polygon_endpoint
        self.condition_blockchain_endpoints = dict(self._original_condition_endpoints)
        self._active = False
        self._process = None

    @property
    def health_url(self) -> Optional[str]:
        """eRPC health check URL, or None if not running."""
        if self._active:
            return self._erpc_config.health_url
        return None

    def status_info(self) -> Dict[str, Any]:
        """Return eRPC proxy status for inclusion in Ursula's status JSON."""
        info: Dict[str, Any] = {
            "active": self._active,
        }
        if not self._active:
            return info

        info["pid"] = self._process.pid if self._process else None
        info["server_port"] = self._erpc_config.server_port
        info["metrics_port"] = self._erpc_config.metrics_port
        info["health_url"] = self.health_url

        # Proxied endpoints
        info["eth_endpoint"] = self.eth_endpoint
        info["polygon_endpoint"] = self.polygon_endpoint
        info["condition_blockchain_endpoints"] = {
            str(k): v for k, v in self.condition_blockchain_endpoints.items()
        }

        # Cache config
        cache = self._erpc_config.cache
        if cache and cache.method_ttls:
            info["cache_policies"] = {
                method: f"{ttl}s" for method, ttl in cache.method_ttls.items()
            }

        # Upstream count
        info["upstream_count"] = sum(
            len(urls) for urls in self._erpc_config.upstreams.values()
        )
        info["chains"] = sorted(self._erpc_config.upstreams.keys())

        return info
