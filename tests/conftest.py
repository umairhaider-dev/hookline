import logging
import os
from collections.abc import Iterator
from pathlib import Path

import pytest

from hookline.logging_config import PACKAGE_LOGGER


@pytest.fixture(autouse=True)
def isolated_environment(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Iterator[None]:
    """Keep tests independent of the developer's environment, .env and config files."""
    for name in list(os.environ):
        if name.upper().startswith("HOOKLINE_") or name.upper() == "ANTHROPIC_API_KEY":
            monkeypatch.delenv(name)
    monkeypatch.chdir(tmp_path)
    yield
    package_logger = logging.getLogger(PACKAGE_LOGGER)
    for handler in list(package_logger.handlers):
        package_logger.removeHandler(handler)
    package_logger.setLevel(logging.NOTSET)
