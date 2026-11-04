# Sending Hookline verdicts to Watchpost

`hookline push` uploads analysed emails to Watchpost as JSON events through its
ingest API (`POST /api/ingest/uploads`, parser `json`). The two rules in
`rules/` turn those events into alerts mapped to ATT&CK T1566 (Phishing), one
alert per email:

| Rule | Event | Severity |
| --- | --- | --- |
| `hookline-malicious-email` | `event.action: hookline_email_malicious` | high |
| `hookline-suspicious-email` | `event.action: hookline_email_suspicious` | medium |

## Setup

1. Add both rules to Watchpost: paste each file on the **Rules** page, or
   copy them into Watchpost's rules folder.
2. Give Hookline credentials for a Watchpost user with the analyst or admin
   role. They are read only from the environment:

   ```bash
   export WATCHPOST_TOKEN=...            # from POST /api/auth/token
   # or
   export WATCHPOST_USERNAME=hookline WATCHPOST_PASSWORD=...
   ```

3. Push:

   ```bash
   hookline push suspicious.eml --url https://watchpost.example.com --wait
   hookline push reports/*.json --min-verdict malicious
   hookline push samples/credential-phish.eml --dry-run    # print the events only
   ```

## What an event holds

| Field | Value |
| --- | --- |
| `@timestamp` | The email's Date header (the analysis time if it has none) |
| `event.action` | `hookline_email_malicious`, `_suspicious` or `_likely_safe` |
| `event.code` | SHA-256 of the raw email, so alerts group per email |
| `user.name` | The first recipient |
| `source.ip` | The first external sending IP |
| `url.original` | The first URL listed as an IOC |
| `message` | Verdict, score, sender and subject |
| `hookline` | Findings, IOCs, ATT&CK techniques, recommended actions and the AI summary |

Only emails with at least the `suspicious` verdict are pushed by default
(`--min-verdict` or `min_verdict` in `[watchpost]`). The event contains nothing
that changes between runs, so pushing the same report twice stores it once.
The URL comes from `--url`, then `WATCHPOST_URL`, then `url` in `[watchpost]`;
HTTPS is verified (`ca_bundle` adds a private CA).
