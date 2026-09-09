"""Container health check that performs no network activity."""

from __future__ import annotations

import ssl
from pathlib import Path


def main() -> int:
    import fastmcp  # noqa: F401
    import httpx  # noqa: F401
    import netmiko  # noqa: F401
    import pysnmp  # noqa: F401

    trust_paths = ssl.get_default_verify_paths()
    assert trust_paths.cafile and Path(trust_paths.cafile).is_file()
    assert ssl.create_default_context().get_ca_certs(binary_form=True)
    assert Path("/var/lib/netops-helper").is_dir()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
