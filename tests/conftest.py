import logging
import os
import socket
from collections.abc import Iterator
from pathlib import Path

import pytest

from hookline.logging_config import PACKAGE_LOGGER

_KEY_VARIABLES = frozenset(
    {"ANTHROPIC_API_KEY", "VIRUSTOTAL_API_KEY", "ABUSEIPDB_API_KEY", "URLHAUS_AUTH_KEY"}
)


def _no_network(*args: object, **kwargs: object) -> None:
    raise RuntimeError("tests must not open network connections")


@pytest.fixture(autouse=True)
def isolated_environment(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Iterator[None]:
    """Keep tests independent of the developer's environment, files and the network."""
    for name in list(os.environ):
        if name.upper().startswith("HOOKLINE_") or name.upper() in _KEY_VARIABLES:
            monkeypatch.delenv(name)
    monkeypatch.setattr(socket.socket, "connect", _no_network)
    monkeypatch.chdir(tmp_path)
    yield
    package_logger = logging.getLogger(PACKAGE_LOGGER)
    for handler in list(package_logger.handlers):
        package_logger.removeHandler(handler)
    package_logger.setLevel(logging.NOTSET)
