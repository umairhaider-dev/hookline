import runpy
import sys

import pytest

from hookline import __version__


def test_python_dash_m_entry_point(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(sys, "argv", ["hookline", "--version"])
    with pytest.raises(SystemExit) as exit_info:
        runpy.run_module("hookline", run_name="__main__")
    assert exit_info.value.code == 0
    assert capsys.readouterr().out.strip() == f"hookline {__version__}"
