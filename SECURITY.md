# Security policy

Hookline reads hostile input by design: every email it analyses may have been
written by an attacker. Bugs that let an email do something it should not are
the ones that matter most, for example:

- a link being fetched or an attachment being opened or executed;
- text from an email lowering a score, or steering the model past the
  defences described in [docs/ai-security.md](docs/ai-security.md);
- script or markup from an email running in the HTML report or web interface;
- an API key or redacted personal data reaching a log, a report or a cloud
  model.

## Reporting a vulnerability

Please report it privately through
[GitHub's private vulnerability reporting](https://github.com/umairhaider-dev/hookline/security/advisories/new)
rather than in a public issue. Include the Hookline version, the command or
request you ran, and a minimal `.eml` that shows the problem, built from
fictional data.

Only the latest version on `main` receives fixes.
