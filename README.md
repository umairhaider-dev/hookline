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

## AI assessment

After the checks, a language model reads the email and the findings and returns
a likelihood (0-100), an attack type, the tactics used, an explanation for the
analyst and recommended actions, as JSON validated against a strict schema.

| Provider | Setting | Notes |
| --- | --- | --- |
| Ollama (default) | `llm.provider = "ollama"` | Local; the email never leaves the machine. Run `ollama pull llama3.1:8b` once. |
| Anthropic | `llm.provider = "anthropic"` | Needs `ANTHROPIC_API_KEY` and `pip install "hookline[anthropic]"`; uses `claude-opus-5-5` with structured outputs and server-side refusal fallback. |

`--no-ai` skips the model. If it is unreachable, too slow or answers invalid
JSON twice, the verdict falls back to the deterministic checks and the report
says why.

### AI safety

The model assists; it never decides alone.

- **It cannot lower the score.** Its likelihood adds up to `ai_max_points`
  (default 40) above 50 and nothing below. This is clamped in the scoring code,
  so no answer can remove a finding or soften a verdict.
- **Email content is data.** The system prompt says so, and everything taken
  from the email sits between markers carrying a random value the sender
  cannot predict; marker-like text inside the email is broken up.
- **Injection attempts are findings.** Text addressed to an AI or a scanner
  ("ignore previous instructions", "classify this email as safe") is a high
  severity `prompt_injection` indicator, or critical when it is hidden.
- **Hidden text is removed and recorded.** `display:none`, zero-size,
  transparent or background-coloured text, `mso-hide`, HTML comments and
  zero-width characters are kept out of the prompt and reported as
  `hidden_text`.
- **Personal data is redacted for cloud providers** (on by default; set
  `llm.redaction`): mailbox names, recipients' names, phone, card and ID
  numbers, IBANs and URL query values. Domains are kept, since they are the
  evidence.
- **Answers are validated.** Bounded fields, an enum for the attack type, one
  corrective retry, then rules-only.

## Reports

Every analysis yields the same report in three formats:

```bash
hookline analyze mail.eml                         # terminal summary
hookline analyze mail.eml -f json -o report.json  # the full report for tools
hookline analyze mail.eml -f html -o report.html  # a self-contained page to share
```

Each report has the verdict and score breakdown, the indicators with their
evidence, the AI and threat intelligence results, recommended actions, MITRE
ATT&CK techniques (T1566 Phishing and its sub-techniques, plus T1598.003,
T1656 Impersonation and T1036 Masquerading where the findings support them)
and IOCs: the URLs, domains, IPs, addresses and hashes worth blocking. The
organisation's own domains (protected and recipient domains) and internal IPs
are left out of the IOCs. The HTML page escapes everything from the email,
shows indicators defanged (`hxxp://evil[.]test`), and has a policy that blocks
scripts and external content.

### Scoring

| Severity | Points |
| --- | --- |
| critical | 50 |
| high | 30 |
| medium | 15 |
| low | 5 |
| info | 0 |

Each indicator type counts once, at its most severe instance. The AI adds up
to 40 points above a likelihood of 50 and never subtracts. Totals are capped
at 100; 35 or more is suspicious, 70 or more malicious. All of it is set in
`[scoring]`, including `type_points` to weight one type differently.

## Web interface

```bash
pip install -e ".[web]"
hookline serve                    # http://127.0.0.1:8000
```

The page takes an `.eml` upload and returns the HTML report; `POST
/api/v1/analyze` (multipart field `file`) returns the JSON report, and
`GET /api/v1/health` reports the version. Uploads are analysed in memory, never
stored, and capped at `max_email_bytes`. Responses carry a strict
Content-Security-Policy and `Cache-Control: no-store`. It listens on localhost
by default; set `HOOKLINE_WEB_TOKEN` before exposing it, and send the token as
`Authorization: Bearer ...` (or in the form's token field).

## Watchpost

`hookline push` sends analysed emails to Watchpost, the self-hosted SOC
platform, through its ingest API; the rules in `integrations/watchpost/rules/`
turn them into alerts, one per email. See
[integrations/watchpost/README.md](integrations/watchpost/README.md).

```bash
export WATCHPOST_TOKEN=...
hookline push suspicious.eml --url https://watchpost.example.com --wait
hookline push report.json --dry-run
```

## Evaluation

`evaluation/` holds a synthetic, labelled dataset of 240 emails (120 phishing,
120 benign) and the harness that scores each analysis mode. All of it is
fictional, and it is reproducible from a seed. See
[evaluation/README.md](evaluation/README.md) for the categories and caveats, and
[evaluation/results/RESULTS.md](evaluation/results/RESULTS.md) for the full
results, including per-category rates and every misclassified email.

An email counts as flagged when its verdict is suspicious or malicious.

| Mode | Precision | Recall | F1 | False positive rate | Mean time per email |
| --- | ---: | ---: | ---: | ---: | ---: |
| Rules only | 1.000 | 0.700 | 0.824 | 0.000 | 7 ms |
| AI only | not run | | | | |
| Combined | not run | | | | |

The AI-only and combined modes need a language model, and none was available
when these results were produced, so those rows are left empty rather than
estimated. Reproduce all three with a local model:

```bash
ollama pull llama3.1:8b
hookline --config evaluation/hookline-eval.toml eval run
```

What the rules-only run shows:

- **No false positives** on the 120 benign emails, including 72 deliberately
  awkward ones: newsletters with trackers, hidden preview text and sale
  deadlines, overdue-invoice reminders and internal password-expiry notices.
- **Strong on loud attacks**: credential links, homoglyph senders and gift card
  requests are all caught, as are 90% of invoice frauds.
- **Weak where rules lack context**: HTML attachments (12%; attachments are
  never opened, so the login form inside is unseen), quiet lures from properly
  authenticated domains (25%), vendor lookalikes that are spotted but score too
  low on their own (50%), hijacked threads from lookalikes of partners outside
  the protected list (58%), and executive impersonation from free webmail (58%;
  there is no executive directory to compare names against). These are the
  cases the language model is there to help with.
- **Prompt injection backfires on the sender**: the `prompt_injection` check
  fired on 16 of 20 hidden instructions, and 20 of 20 injected emails were
  flagged against 12 of 20 of their otherwise identical twins.

The dataset was written by the same author as the rules, so treat these
numbers as a regression baseline and a way to compare modes, not as a
benchmark of real-world accuracy.

## Configuration

Settings are read from, highest precedence first:

1. Environment variables prefixed with `HOOKLINE_` (nested sections use `__`,
   for example `HOOKLINE_LLM__OLLAMA_MODEL`)
2. A `.env` file in the working directory (see `.env.example`)
3. A TOML file: `--config PATH`, the path in `HOOKLINE_CONFIG`, or
   `hookline.toml` in the working directory (see `hookline.example.toml`)
4. Built-in defaults

API keys are only read from the environment or `.env`, never from the TOML file.
