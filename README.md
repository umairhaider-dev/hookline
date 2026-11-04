# Hookline

Hookline analyzes suspicious emails (`.eml` files) for SOC analysts. Deterministic
security checks produce the evidence, a language model adds context and a
plain-language explanation, and a transparent scoring step combines the two into
a verdict: **malicious**, **suspicious** or **likely safe**.

The language model assists; it never decides alone. It cannot remove or override
a deterministic finding, and the tool works fully in rules-only mode when no
model is available.

> Work in progress. Full documentation, architecture and evaluation results will
> land here as the project matures.

## Development setup

Requires Python 3.11 or newer.

```bash
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
pre-commit install
```

Run the checks:

```bash
ruff check .
ruff format --check .
mypy
pytest
```

Try it:

```bash
hookline analyze samples/credential-phish.eml
hookline analyze samples/credential-phish.eml --format json
hookline --config hookline.example.toml analyze samples/homoglyph-bank.eml
hookline --config hookline.example.toml config
```

The `samples/` folder holds fictional messages (reserved `.test` domains and
documentation IP ranges): a benign meeting note, a credential phish, a gift-card
request, a payroll lure with disguised attachments, and a bank lookalike that
uses a Cyrillic letter. The example config protects their fictional company
domains, which turns on the lookalike and display-name checks for them.

## Deterministic checks

Every finding is an indicator with a type, severity, value and the evidence
behind it.

| Area | What is checked |
| --- | --- |
| Authentication | SPF, DKIM and DMARC results, using only trusted or topmost Authentication-Results headers |
| Sender | Reply-To and Return-Path domains against From; display names that claim another address, domain or protected brand |
| Received chain | External sending IP addresses, newest first |
| Domains | Typosquats (edit distance), lookalike characters, punycode, protected names in subdomains or combined with other words, high-risk TLDs |
| Links | Text that shows a different destination, raw or disguised IP hosts, shorteners, `@` tricks, heavy encoding, recipient addresses hidden in base64, login-style paths, embedded forms |
| Attachments | SHA-256, real type from magic bytes versus extension and declared type, double extensions and text-direction tricks, risky formats, risky files inside ZIP archives, encrypted archives |
| Language | Urgency and secrecy, credential requests, payment and bank-detail changes, gift cards (English only) |

Links are never fetched and attachments are never opened: URLs are analysed as
text, and attachments are only hashed and identified from their leading bytes
and, for ZIP files, their file list.

## Threat intelligence (optional)

With API keys set in the environment or `.env`, Hookline looks up the email's
attachment hashes, URLs, sending IPs and domains:

| Provider | Key variable | Looks up |
| --- | --- | --- |
| URLhaus (abuse.ch) | `URLHAUS_AUTH_KEY` | URLs, hosts, file hashes |
| AbuseIPDB | `ABUSEIPDB_API_KEY` | IP addresses |
| VirusTotal | `VIRUSTOTAL_API_KEY` | file hashes, URLs, domains, IP addresses |

- Nothing runs without a key, and `--no-intel` turns lookups off for one run, so
  the tool works fully offline.
- Values are only looked up, never submitted for scanning, and URLs are never
  visited. Private and reserved IPs, internal or reserved host names and the
  protected domains never leave the machine. Set `lookup_urls = false` if URLs
  in your mail carry tokens you would rather not share.
- Answers are cached in `.hookline-cache/` (24 hours by default) and each
  provider has a request budget that matches its free tier. The request log is
  shared between runs, so the limits hold across separate commands.
  `hookline clear-cache` empties it.
- Timeouts, rejected keys and exhausted quotas are reported in the report, and
  the provider is skipped for the rest of the message instead of failing every
  lookup in turn.
- A malicious answer adds a critical `threat_intel_match` indicator; a
  suspicious one adds a medium one.

## Configuration

Settings are read from, highest precedence first:

1. Environment variables prefixed with `HOOKLINE_` (nested sections use `__`,
   for example `HOOKLINE_LLM__OLLAMA_MODEL`)
2. A `.env` file in the working directory (see `.env.example`)
3. A TOML file: `--config PATH`, the path in `HOOKLINE_CONFIG`, or
   `hookline.toml` in the working directory (see `hookline.example.toml`)
4. Built-in defaults

API keys are only read from the environment or `.env`, never from the TOML file.
