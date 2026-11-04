"""Allow ``python -m hookline``."""

from hookline.cli import app

if __name__ == "__main__":
    app(prog_name="hookline")
