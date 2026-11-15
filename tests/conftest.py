import logging
import os
import socket
import threading
from collections.abc import Iterator
from pathlib import Path

import pytest

from hookline.logging_config import PACKAGE_LOGGER

_KEY_VARIABLES = frozenset(
    {
        "ANTHROPIC_API_KEY",
        "VIRUSTOTAL_API_KEY",
        "ABUSEIPDB_API_KEY",
        "URLHAUS_AUTH_KEY",
        "WATCHPOST_URL",
        "WATCHPOST_TOKEN",
        "WATCHPOST_USERNAME",
        "WATCHPOST_PASSWORD",
    }
)


_LOCAL_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})
_real_getaddrinfo = socket.getaddrinfo
_real_connect = socket.socket.connect
_real_socketpair = socket.socketpair
_inside_socketpair = threading.local()


def _no_network(self: socket.socket, address: object) -> None:
    if getattr(_inside_socketpair, "active", False):
        _real_connect(self, address)  # type: ignore[arg-type]
        return
    # Behave like a machine with nothing listening, so code under test takes
    # its normal "unreachable" path instead of crashing.
    raise ConnectionRefusedError("tests must not open network connections")


def _socketpair(*args: object, **kwargs: object) -> tuple[socket.socket, socket.socket]:
    # asyncio's event loop needs a socket pair, which Windows builds from a
    # loopback connection; that one connection is allowed.
    _inside_socketpair.active = True
    try:
        return _real_socketpair(*args, **kwargs)  # type: ignore[arg-type]
    finally:
        _inside_socketpair.active = False


def _local_names_only(host: object, *args: object, **kwargs: object) -> object:
    if host not in _LOCAL_HOSTS:
        raise socket.gaierror(f"tests must not resolve {host!r}")
    return _real_getaddrinfo(host, *args, **kwargs)  # type: ignore[arg-type]


@pytest.fixture(autouse=True)
def isolated_environment(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Iterator[None]:
    """Keep tests independent of the developer's environment, files and the network."""
    for name in list(os.environ):
        if name.upper().startswith("HOOKLINE_") or name.upper() in _KEY_VARIABLES:
            monkeypatch.delenv(name)
    monkeypatch.setattr(socket.socket, "connect", _no_network)
    monkeypatch.setattr(socket, "socketpair", _socketpair)
    monkeypatch.setattr(socket, "getaddrinfo", _local_names_only)
    monkeypatch.chdir(tmp_path)
    yield
    package_logger = logging.getLogger(PACKAGE_LOGGER)
    for handler in list(package_logger.handlers):
        package_logger.removeHandler(handler)
    package_logger.setLevel(logging.NOTSET)
