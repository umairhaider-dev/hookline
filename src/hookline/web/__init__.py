"""Web upload page and JSON API. Needs the optional extra: ``pip install "hookline[web]"``."""

from hookline.web.app import API_PREFIX, create_app

__all__ = ["API_PREFIX", "create_app"]
