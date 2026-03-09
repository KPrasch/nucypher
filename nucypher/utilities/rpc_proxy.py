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


# ---------------------------------------------------------------------------
# Twisted ProcessProtocol for eRPC lifecycle management
# ---------------------------------------------------------------------------


class ERPCProcessProtocol:
    """Twisted ProcessProtocol that manages the eRPC child process.

    Replaces polling-based health checks with event-driven lifecycle
    management: ``processEnded`` fires immediately on child death,
    enabling automatic restart with exponential backoff.
    """

    MAX_RESTARTS = 3
    BASE_BACKOFF = 2  # seconds

    def __init__(self, proxy: "RPCProxy"):
        from twisted.internet import protocol

        # Dynamically subclass ProcessProtocol so tests can instantiate
        # without importing twisted at module level.
        self._proxy = proxy
        self.log = Logger("eRPC")
        self._restart_count = 0
        self._intentional_stop = False
        self._stderr_buffer = b""

        # Build the actual Twisted ProcessProtocol
        outer = self

        class _Protocol(protocol.ProcessProtocol):
            def connectionMade(self_inner):
                outer.log.info(
                    "eRPC process connected (PID {pid})",
                    pid=self_inner.transport.pid,
                )

            def errReceived(self_inner, data):
                outer._stderr_buffer += data
                # Keep buffer bounded
                if len(outer._stderr_buffer) > 8192:
                    outer._stderr_buffer = outer._stderr_buffer[-4096:]

            def processEnded(self_inner, reason):
                outer._on_process_ended(reason)

        self._protocol = _Protocol()

    @property
    def protocol(self):
        """The underlying Twisted ProcessProtocol instance."""
        return self._protocol

    @property
    def pid(self) -> Optional[int]:
        """PID of the managed process, or None."""
        transport = self._protocol.transport
        if transport is not None:
            return transport.pid
        return None

    def mark_intentional_stop(self):
        """Mark that the next process exit is intentional (no restart)."""
        self._intentional_stop = True

    def reset_restart_count(self):
        """Reset the restart counter (e.g. after successful health check)."""
        self._restart_count = 0

    def _on_process_ended(self, reason):
        """Handle eRPC process termination."""
        from twisted.internet import error, reactor

        exit_code = reason.value.exitCode if hasattr(reason.value, "exitCode") else None

        if self._intentional_stop:
            self.log.info("eRPC process stopped (exit code {code})", code=exit_code)
            self._proxy._on_stopped()
            return

        self.log.warn(
            "eRPC process died unexpectedly (exit code {code})",
            code=exit_code,
        )

        if self._stderr_buffer:
            stderr_text = self._stderr_buffer.decode(errors="replace")[-500:]
            self.log.warn("eRPC stderr: {stderr}", stderr=stderr_text)

        if self._restart_count >= self.MAX_RESTARTS:
            self.log.warn(
                "eRPC restart limit reached ({max}), falling back to direct endpoints",
                max=self.MAX_RESTARTS,
            )
            self._proxy._fallback()
            return

        self._restart_count += 1
        delay = self.BASE_BACKOFF ** self._restart_count
        self.log.info(
            "Restarting eRPC in {delay}s (attempt {n}/{max})",
            delay=delay,
            n=self._restart_count,
            max=self.MAX_RESTARTS,
        )

        reactor.callLater(delay, self._proxy._do_spawn)


class RPCProxy:
    """Manages the eRPC proxy process alongside Ursula.

    Uses Twisted's ``reactor.spawnProcess`` for event-driven process
    lifecycle management. The eRPC child process is monitored via
    ``ProcessProtocol.processEnded`` — no polling required. If the
    process dies unexpectedly, it is automatically restarted with
    exponential backoff (up to 3 attempts) before falling back to
    direct RPC endpoints.

    Designed to be instantiated during Ursula startup and stopped during
    shutdown. If the proxy fails to start, falls back silently to direct
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

        self._process_protocol: Optional[ERPCProcessProtocol] = None
        self._active = False
        self._binary_path: Optional[str] = None
        self._config_file_path = None
        self._shutdown_trigger_id = None

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

    @property
    def pid(self) -> Optional[int]:
        """PID of the running eRPC process, or None."""
        if self._process_protocol:
            return self._process_protocol.pid
        return None

    def start(self, health_timeout: int = 30) -> bool:
        """Start the eRPC proxy process using Twisted's reactor.

        Returns ``True`` if the proxy started successfully, ``False`` on
        fallback to direct endpoints.
        """
        try:
            from erpc.process import find_erpc_binary
        except ImportError:
            self.log.warn("erpc-py is not installed — running without RPC proxy")
            return False

        try:
            self._binary_path = find_erpc_binary()
        except Exception as e:
            self.log.warn(
                "eRPC binary not found — running without RPC proxy: {err}",
                err=str(e),
            )
            return False

        # Write the config file for the eRPC binary
        try:
            self._config_file_path = self._erpc_config.write()
        except Exception as e:
            self.log.warn("Failed to write eRPC config: {err}", err=str(e))
            return False

        # Spawn the process via Twisted reactor
        if not self._do_spawn():
            self._fallback()
            return False

        # Wait for health synchronously (startup only)
        if not self._wait_for_health(timeout=health_timeout):
            self.log.warn(
                "eRPC proxy failed health check — falling back to direct endpoints"
            )
            self.stop()
            return False

        # Rewrite endpoints to route through proxy
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
        self.log.info("eRPC proxy started (PID {pid})", pid=self.pid)

        # Register reactor shutdown hook (replaces atexit)
        try:
            from twisted.internet import reactor

            self._shutdown_trigger_id = reactor.addSystemEventTrigger(
                "before", "shutdown", self.stop
            )
        except Exception:
            pass  # Best-effort

        # Reset restart counter on successful startup
        if self._process_protocol:
            self._process_protocol.reset_restart_count()

        return True

    def _do_spawn(self) -> bool:
        """Spawn the eRPC process via Twisted reactor.

        Returns True if the process was spawned, False on error.
        This method is also called by ERPCProcessProtocol for restarts.
        """
        from twisted.internet import reactor

        try:
            self._process_protocol = ERPCProcessProtocol(self)
            command = [self._binary_path, str(self._config_file_path)]

            reactor.spawnProcess(
                self._process_protocol.protocol,
                self._binary_path,
                args=command,
                env=os.environ,
            )
            return True
        except Exception:
            import traceback as _tb

            self.log.warn(
                "Failed to spawn eRPC process:\n{tb}",
                tb=_tb.format_exc().rstrip(),
            )
            return False

    def _wait_for_health(self, timeout: int = 30) -> bool:
        """Synchronous health check — used only during initial startup."""
        import time

        deadline = time.monotonic() + timeout
        health_url = self._erpc_config.health_url

        while time.monotonic() < deadline:
            try:
                import urllib.request

                with urllib.request.urlopen(health_url, timeout=2) as resp:
                    if resp.status == 200:
                        return True
            except Exception:
                pass
            time.sleep(0.5)

        return False

    def stop(self) -> None:
        """Stop the eRPC proxy and restore original endpoints."""
        if self._process_protocol:
            self._process_protocol.mark_intentional_stop()
            transport = self._process_protocol.protocol.transport
            if transport is not None:
                try:
                    transport.signalProcess("TERM")
                except Exception:
                    try:
                        transport.signalProcess("KILL")
                    except Exception:
                        pass
            self.log.info("eRPC proxy stopped")

        # Remove shutdown trigger to avoid double-stop
        if self._shutdown_trigger_id is not None:
            try:
                from twisted.internet import reactor

                reactor.removeSystemEventTrigger(self._shutdown_trigger_id)
            except Exception:
                pass
            self._shutdown_trigger_id = None

        # Clean up config file
        if self._config_file_path:
            try:
                import pathlib

                pathlib.Path(self._config_file_path).unlink(missing_ok=True)
            except Exception:
                pass

        self._fallback()

    def _on_stopped(self) -> None:
        """Called by ERPCProcessProtocol when process exits after intentional stop."""
        # Already handled by stop() — this is just the protocol callback
        pass

    def _fallback(self) -> None:
        """Restore original endpoints (direct RPC, no proxy)."""
        self.eth_endpoint = self._original_eth_endpoint
        self.polygon_endpoint = self._original_polygon_endpoint
        self.condition_blockchain_endpoints = dict(self._original_condition_endpoints)
        self._active = False

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

        info["pid"] = self.pid
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

        # Restart tracking
        if self._process_protocol:
            info["restarts"] = self._process_protocol._restart_count

        return info
