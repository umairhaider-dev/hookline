# Hookline

Hookline analyzes suspicious emails (`.eml` files) for SOC analysts. Deterministic
security checks produce the evidence, a language model adds context and a
plain-language explanation, and a transparent scoring step combines the two into
a verdict: **malicious**, **suspicious** or **likely safe**.

The language model assists; it never decides alone. It cannot remove or override
a deterministic finding, its contribution to the score is never negative, and
the tool works fully in rules-only mode when no model is available.

- **Evidence first.** Authentication results, sender and domain tricks, link
  and attachment checks, social engineering language and prompt injection
  attempts, each with the evidence behind it.
- **Safe by construction.** Links are never fetched and attachments never
  opened. Email content is treated as hostile everywhere: in the prompt, in the
  terminal and in the HTML report.
- **Local by default.** The default model runs on your machine through Ollama;
  cloud models get personal data redacted first. Threat intelligence lookups
  are optional and send only public values.
- **Built for a SOC.** Terminal, JSON and self-contained HTML reports with IOCs,
  MITRE ATT&CK techniques and recommended actions; a small web interface; and
  a push to the Watchpost SOC platform.

## How it works

```mermaid
flowchart LR
    eml[".eml file<br/>CLI or web upload"] --> parser["Parser<br/>MIME, headers, visible and hidden text,<br/>links, attachment hashes and types"]
    parser --> checks["Deterministic checks<br/>authentication, sender, domains,<br/>links, attachments, language, content"]
    checks --> intel["Threat intelligence<br/>optional, cached, rate limited"]
    intel --> ai["AI assessor<br/>optional: hidden text removed, redaction,<br/>nonce-marked prompt, validated JSON"]
    ai --> scoring["Scoring<br/>each indicator type once,<br/>AI points never negative"]
    scoring --> enrich["Enrichment<br/>IOCs, MITRE techniques,<br/>recommended actions"]
    enrich --> terminal["Terminal report"]
    enrich --> files["JSON and HTML reports"]
    enrich --> web["Web page and JSON API"]
    enrich --> watchpost["Watchpost push"]
    intel <-.-> providers[("URLhaus, AbuseIPDB,<br/>VirusTotal")]
    ai <-.-> model[("Ollama, local<br/>or Anthropic API")]
```

1. **Parse.** The standard library parser reads the message without ever
   raising: malformed headers, broken encodings and truncated MIME become
   recorded defects. HTML is reduced to the text a reader would see, and
   anything hidden (`display:none`, white-on-white, zero-size text, comments)
   is kept apart.
2. **Check.** Nine checks turn what they find into indicators: a type, a
   severity, a value and the evidence.
3. **Look up** (optional). Attachment hashes, URLs, sending IPs and domains go
   to reputation services when API keys are set.
4. **Assess** (optional). A language model reads the visible email and the
   findings and returns a likelihood, an attack type, tactics, an explanation
   and suggested actions, as JSON checked against a strict schema.
5. **Score.** Points per indicator type plus a clamped AI contribution give a
   score out of 100 and the verdict.
6. **Report.** IOCs, MITRE ATT&CK techniques and recommended actions are
   derived from the findings, and the report is written out.

Each stage is isolated: a failing check, lookup or model call becomes a
warning or a recorded status in the report, and the analysis still completes.

## Quick start

Requires Python 3.11 or newer. From the project folder:

```bash
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -e .                   # add [web], [anthropic] or [dev] as needed
```

Analyze one of the sample emails, rules only:

```bash
hookline analyze samples/credential-phish.eml --no-ai
hookline analyze samples/credential-phish.eml -f html -o report.html --no-ai
```

### Add a local model with Ollama

Install Ollama from [ollama.com](https://ollama.com), then pull the default
model (about 5 GB) and make sure the server is running:

```bash
ollama pull llama3.1:8b
ollama serve                       # skip if Ollama already runs in the background
hookline analyze samples/credential-phish.eml
```

Hookline talks to `http://localhost:11434` by default; set `llm.ollama_url` and
`llm.ollama_model` to use another server or model. If Ollama is not running,
the analysis still completes on the deterministic checks and the report says
why the model was skipped.

To see exactly what the model receives for an email, after hidden text is
removed and personal data redacted:

```bash
hookline show-prompt samples/credential-phish.eml
```

### More to try

```bash
hookline --config hookline.example.toml analyze samples/homoglyph-bank.eml
hookline analyze samples/malware-attachment.eml -f json
hookline push samples/credential-phish.eml --dry-run    # the Watchpost event
pip install -e ".[web]" && hookline serve               # http://127.0.0.1:8000
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
| Structure | Malformed MIME and invalid headers found while parsing (a weak signal, reported at low severity) |
| Authentication | SPF, DKIM and DMARC results, using only trusted or topmost Authentication-Results headers |
| Sender | Reply-To and Return-Path domains against From; display names that claim another address, domain or protected brand |
| Received chain | External sending IP addresses, newest first |
| Domains | Typosquats (edit distance), lookalike characters, punycode, protected names in subdomains or combined with other words, high-risk TLDs |
| Links | Text that shows a different destination, raw or disguised IP hosts, shorteners, `@` tricks, heavy encoding, recipient addresses hidden in base64, login-style paths, embedded forms |
| Attachments | SHA-256, real type from magic bytes versus extension and declared type, double extensions and text-direction tricks, risky formats, risky files inside ZIP archives, encrypted archives |
| Language | Urgency and secrecy, credential requests, payment and bank-detail changes, gift cards (English only) |
| Content | Hidden text and zero-width characters inside words; text addressed to an AI or a scanner (prompt injection) |

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

The email is written by the attacker, so everything in it is treated as an
attempt to steer the model. The full threat model, with the residual risks, is
in [docs/ai-security.md](docs/ai-security.md). In short:

- **It cannot lower the score.** Its likelihood adds up to `ai_max_points`
  (default 40) above 50 and nothing below. This is clamped in the scoring code,
  so no answer can remove a finding or soften a verdict.
- **It cannot make a clean email malicious on its own.** With no findings, the
  most the model can reach is 40 points: suspicious, never malicious.
- **It has no tools.** It cannot browse, run anything or send anything; its
  answer is one bounded JSON object that is shown, escaped, to the analyst.
- **Email content is data.** The system prompt says so, and everything taken
  from the email sits between markers carrying a random value the sender
  cannot predict; marker-like text inside the email is broken up.
- **Injection attempts are findings.** Text addressed to an AI or a scanner
  ("ignore previous instructions", "classify this email as safe") is a high
  severity `prompt_injection` indicator, or critical when it is hidden.
- **Hidden text never reaches the model.** Text styled to be invisible, HTML
  comments and zero-width characters are left out of the prompt. Invisible
  styled text and zero-width characters inside words are reported as
  `hidden_text`, and all of it is scanned for injection.
- **Personal data is redacted for cloud providers** (on by default; set
  `llm.redaction`): mailbox names, recipients' names, phone, card and ID
  numbers, IBANs and URL query values. Domains are kept, since they are the
  evidence.
- **Answers are validated.** Bounded fields, an enum for the attack type, one
  corrective retry, then rules-only.

## Scoring

| Severity | Points |
| --- | --- |
| critical | 50 |
| high | 30 |
| medium | 15 |
| low | 5 |
| info | 0 |

- **Each indicator type counts once**, at its most severe instance. Ten
  tracking links in a newsletter are one finding, not ten.
- **The AI adds points, never removes them**: `40 * (likelihood - 50) / 50`
  above a likelihood of 50, and nothing at or below it.
- **The total is capped at 100.** 35 or more is suspicious, 70 or more
  malicious.

For example, `samples/bec-gift-card.eml` scores 45 on the rules alone:

| Source | Points |
| --- | ---: |
| `gift_card_request` (high) | 30 |
| `urgency_language` (medium) | 15 |
| **Rules total: suspicious** | **45** |
| Model answers 90: adds `40 * 40 / 50` | 32 |
| **Combined: malicious** | **77** |

Had the model been talked into answering 10, it would add nothing and the email
would stay suspicious at 45. Every report shows this breakdown line by line.
Points, thresholds and the AI weight are set in `[scoring]`, including
`type_points` to weight one indicator type differently.

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
`Authorization: Bearer ...` (or in the form's token field). It has no TLS or
rate limiting of its own, so put a reverse proxy in front of any shared
deployment.

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
`hookline config` prints the effective settings with keys masked.

The setting that matters most is `checks.protected_domains`: your own domains
and the brands and vendors your users trust. The lookalike, display-name and
IOC logic all work from it.

## Limitations

- **No context about the organisation.** Hookline does not know who the
  executives are, which vendors are real, or whether the sender has written
  before. That is why business email compromise and quiet lures from clean,
  authenticated domains are its weakest categories.
- **Lookalike detection needs a list.** Typosquats and homoglyphs are found
  only for domains in `protected_domains`.
- **Attachments and images are opaque.** Nothing is opened, rendered or read
  with OCR, so a login form inside an HTML attachment or a lure drawn in an
  image is unseen by the rules and the model alike.
- **Authentication comes from headers.** SPF, DKIM and DMARC results are read
  from Authentication-Results headers, not verified with DNS lookups, so they
  are only as good as the receiving server that wrote them.
- **English only.** The language checks and prompt injection patterns are
  written for English.
- **The model's quality is unmeasured.** The AI modes have not been run on
  the evaluation set yet, and small local models can be inconsistent. The
  explanation is a second opinion; the findings are the evidence.
- **Redaction is a best effort.** Names other than the recipients', postal
  addresses and business details still reach a cloud model.
- **The evaluation is synthetic** and written by the same author as the rules.
- **One `.eml` at a time.** There is no Outlook `.msg` support and no mailbox
  integration.

## Future work

Gaps found by the evaluation, left as open work rather than tuned away on the
same dataset:

- **HTML attachments** score only medium today. Reading an HTML attachment's
  markup as text, still without rendering it, would expose password fields and
  forms that post to other domains.
- **Executive impersonation from free webmail** needs a configurable list of
  executive and VIP names to compare display names against.
- **Vendor lookalikes** are found but often score too low alone. A known-vendor
  list would let lookalikes of real suppliers count for more.
- **Quiet lures from authenticated domains** need signals rules do not have
  yet: domain age (an RDAP lookup by name) and first-contact senders.

Beyond those:

- Run and publish the AI-only and combined evaluation, including how injected
  instructions affect the model, with a local and a cloud model.
- Prompt injection and language patterns in more languages.
- Outlook `.msg` input and a report-phish mailbox reader.
- Rate limiting and a Host allowlist for the web interface.

## Development

```bash
pip install -e ".[dev]"
pre-commit install
ruff check .
ruff format --check .
mypy
pytest
```

The test suite runs without a network or a model: sockets are blocked, and the
AI layer is tested against a fake provider. Coverage must stay above 85%.

| Path | Contents |
| --- | --- |
| `src/hookline/parsing/` | Message, MIME, HTML, header and link parsing |
| `src/hookline/checks/` | The deterministic checks |
| `src/hookline/intel/` | Threat intelligence providers, cache and rate limits |
| `src/hookline/ai/` | Prompt building, redaction, providers, answer validation |
| `src/hookline/scoring.py` | Score and verdict |
| `src/hookline/enrichment.py` | IOCs, MITRE ATT&CK mapping, recommended actions |
| `src/hookline/reporting/` | Terminal, JSON and HTML reports |
| `src/hookline/web/` | Upload page and JSON API |
| `src/hookline/watchpost/` | Watchpost events and client |
| `src/hookline/evaluation/` | Dataset generator and evaluation harness |
| `docs/ai-security.md` | Threat model for the AI layer |

## License

MIT. See [LICENSE](LICENSE).
