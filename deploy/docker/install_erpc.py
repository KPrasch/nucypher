#!/usr/bin/env python3
"""Install the eRPC binary via erpc-py (best-effort, non-blocking)."""
try:
    from erpc.install import install_erpc
    install_erpc()
except Exception as e:
    print(f"eRPC binary install skipped: {e}")
