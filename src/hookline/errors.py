"""Exception types that Hookline raises deliberately."""


class HooklineError(Exception):
    """Base class for expected, user-facing errors."""


class ConfigError(HooklineError):
    """The configuration file or environment contains invalid settings."""


class InputError(HooklineError):
    """An email file could not be read or is outside the accepted limits."""
