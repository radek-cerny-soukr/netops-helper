"""Long-running PID 1 used by the exec-only MCP sidecar."""

from __future__ import annotations

import signal
import threading


stop = threading.Event()


def _stop(_signum: int, _frame: object) -> None:
    stop.set()


def main() -> None:
    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)
    while not stop.wait(3600):
        pass


if __name__ == "__main__":
    main()

