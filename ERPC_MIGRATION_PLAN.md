# eRPC Migration Plan — Incremental Cleanup

> **Base:** `feature/erpc-sidecar` (PR #43)  
> **Target:** `v7.7.x` (KPrasch fork)  
> **Approach:** Each phase is independently revertable via `NUCYPHER_ERPC_ENABLED`  
> **Principle:** Delete code only when eRPC provably handles it; keep safety-critical caches

---

## Phase 2 — Retry Middleware Removal

**Risk: 🟢 Low | Lines removed: ~158 | Certainty: ✅ High**

eRPC handles all retry/backoff natively with configurable per-upstream policies.
The Python retry middleware is fully redundant when the proxy is active.

### Files

| File | What | Action |
|------|------|--------|
| `blockchain/middleware/retry.py` | `RetryRequestMiddleware` (65 lines) | Delete entire class |
| `blockchain/middleware/retry.py` | `AlchemyRetryRequestMiddleware` (36 lines) | Delete entire class |
| `blockchain/middleware/retry.py` | `InfuraRetryRequestMiddleware` (39 lines) | Delete entire class |
| `blockchain/eth/clients.py` | Retry middleware registration (~18 lines) | Guard with `if not erpc_enabled` |
| `blockchain/middleware/__init__.py` | Module exports | Clean up |

### Implementation

```python
# In clients.py — guard retry middleware injection
from nucypher.utilities.rpc_proxy import is_erpc_enabled

if not is_erpc_enabled():
    # Legacy retry middleware — only needed without eRPC proxy
    self._add_retry_middleware()
```

### Verification
- Run full test suite with `NUCYPHER_ERPC_ENABLED=true` — retry tests should be skipped/adjusted
- Run full test suite with `NUCYPHER_ERPC_ENABLED=false` — behavior unchanged
- Live test on lynx: confirm requests retry through eRPC on provider failures

---

## Phase 3 — Endpoint Manager Simplification

**Risk: 🟡 Medium | Lines removed: ~544 | Certainty: ✅ High**

eRPC provides Go-native connection pooling, health tracking, endpoint selection,
and EWMA-based scoring — all of which `RPCEndpointManager` reimplements in Python.

### Files

| File | What | Action |
|------|------|--------|
| `utilities/endpoint.py` | `ThreadLocalSessionManager` (35 lines) | Delete (Go HTTP client replaces) |
| `utilities/endpoint.py` | `RPCEndpoint` (317 lines) | Delete (eRPC health tracking replaces) |
| `utilities/endpoint.py` | `RPCEndpointManager` (163 lines) | Delete (eRPC failover replaces) |
| `policy/conditions/utils.py` | `ConditionProviderManager` (~90 lines) | Simplify to ~15 lines |
| `policy/conditions/utils.py` | Endpoint sorting by failures/latency (8 lines) | Delete |

### ConditionProviderManager After

```python
class ConditionProviderManager:
    """Routes condition evaluation through the eRPC proxy."""

    def __init__(self, proxy_base_url: str = "http://127.0.0.1:4000"):
        self._proxy_base_url = proxy_base_url

    def supported_chains(self) -> Set[int]:
        # Derived from eRPC config
        ...

    def exec_web3_call(self, chain_id: int, fn, **kwargs):
        """Execute via proxy — single endpoint, eRPC handles the rest."""
        w3 = Web3(HTTPProvider(f"{self._proxy_base_url}/taco-ursula/evm/{chain_id}"))
        return fn(w3=w3)
```

### Verification
- All condition evaluation tests pass
- Live condition check on lynx through proxy
- Confirm endpoint failover works at eRPC level (kill one upstream, verify transparent retry)

---

## Phase 4 — EventScanner Simplification

**Risk: 🟡 Medium | Lines removed: ~200 | Certainty: 🟡 Medium**

eRPC's `getLogsAutoSplittingRangeThreshold` handles range splitting natively.
The adaptive chunking logic becomes redundant for the splitting case, but
chain reorg detection and scanner persistence must stay.

### Files

| File | What | Action |
|------|------|--------|
| `utilities/events.py` | Alchemy chunk reduction logic (~50 lines) | Delete (eRPC splits natively) |
| `utilities/events.py` | Retry/backoff on getLogs failure (~30 lines) | Simplify (eRPC retries) |
| `utilities/events.py` | Rate limiting/throttling (~40 lines) | Delete (eRPC rate-limits per-upstream) |
| `utilities/events.py` | Adaptive chunk sizing (~80 lines) | Simplify (eRPC splits; keep reorg logic) |

### What MUST Stay
- Chain reorg detection + rescan window (safety-critical)
- `JSONifiedState` persistence (last-scanned block tracking)
- Multi-contract event aggregation (application-level orchestration)
- Block timestamp caching (ephemeral optimization)

### eRPC Config Addition
```yaml
getLogsAutoSplittingRangeThreshold: 10000  # per-upstream
```

### Verification
- Event scanning tests with mock providers
- Live DKG event detection on lynx
- Verify large range queries don't hit provider limits

---

## Phase 5 — Architectural Simplification

**Risk: 🟡 Medium | Lines removed: ~265 | Certainty: 🟡 Medium**

With Phases 2-4 complete, deeper structural simplifications become possible.

### 5a. `simple_cache_middleware` Removal

```python
# In clients.py — eRPC handles all caching
if not is_erpc_enabled():
    self._add_simple_cache_middleware()
```

**Lines:** ~3 (middleware registration) + test updates

### 5b. `BlockchainInterfaceFactory` Simplification

With eRPC as single endpoint per chain, the factory's multi-endpoint
management becomes simpler. Each chain maps to one proxy URL.

**Lines:** ~80 simplifiable (not deleted — interface contract stays)

### 5c. `exec_web3_call` Collapse

The elaborate retry-failover-health-scoring call path in
`RPCEndpointManager.call()` becomes a direct Web3 call to the proxy.

**Lines:** Already covered by Phase 3

### 5d. `InterfaceFactory` → Proxy-Aware

```python
@classmethod
def get_or_create_interface(cls, endpoint, *args, **kwargs):
    # If eRPC active, endpoint is already a proxy URL — no special handling
    # Just create/cache the interface normally
    ...
```

---

## Summary

| Phase | Risk | Lines Removed | Files Modified | Dependency |
|-------|------|--------------|----------------|------------|
| 2 — Retry Middleware | 🟢 Low | ~158 | 3 | None |
| 3 — Endpoint Manager | 🟡 Med | ~544 | 3 | Phase 2 |
| 4 — EventScanner | 🟡 Med | ~200 | 1 | Phase 2 |
| 5 — Architecture | 🟡 Med | ~265 | 4 | Phases 2-4 |
| **Total** | | **~1,167** | **11** | |

### Ground Rules
1. Each phase guarded by `is_erpc_enabled()` — legacy code preserved when disabled
2. Tests run in both modes (eRPC on/off) in CI
3. Live validation on lynx before merging each phase
4. No changes to operator-facing config file formats
5. `NUCYPHER_ERPC_ENABLED=false` must always produce identical behavior to pre-eRPC

---

*This plan is based on the exhaustive 42-item RPC infrastructure audit (4 parallel code sweeps)
documented in the Notion knowledge base and `/nucypher-rpc-analysis/`.*
