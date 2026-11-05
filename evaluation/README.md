# Evaluation

`dataset/` holds 240 synthetic, labelled emails (120 phishing, 120 benign)
written by `hookline eval generate` (seed 7). Everything in them is fictional:
the organisation (Larkspur), people, vendors and attackers use reserved `.test`
domains or `example.org`, IP addresses come from documentation ranges, and
attachments are inert bytes that only carry the right file signatures.

```bash
hookline eval generate evaluation/dataset            # rebuild the dataset (same bytes)
hookline --config evaluation/hookline-eval.toml eval run    # all modes if a model answers
hookline --config evaluation/hookline-eval.toml eval run --no-ai
```

`eval run` writes `results/RESULTS.md`, `results/results.json` and
`results/predictions.csv` (one row per email and mode).

## Categories

| Benign | Count | | Phishing | Count |
| --- | ---: | --- | --- | ---: |
| internal memo | 20 | | credential link | 18 |
| meeting invite | 10 | | lookalike sender | 12 |
| newsletter (trackers, hidden preview, sale deadlines) | 20 | | homoglyph sender | 8 |
| vendor invoice (some overdue reminders) | 12 | | HTML attachment | 8 |
| password reset the user asked for | 10 | | malware attachment | 12 |
| shipping notice (some via a shortener) | 12 | | business email compromise | 12 |
| HR announcement with a deadline | 10 | | gift card request | 10 |
| internal password-expiry notice | 8 | | invoice fraud | 10 |
| receipt | 10 | | shortener lure | 6 |
| reply in a thread with a partner | 8 | | low-signal lure | 12 |
| | | | thread hijack | 12 |

Benign categories marked hard in `labels.csv` contain the wording or link
patterns phishing uses. Hard phishing categories (business email compromise,
invoice fraud, low-signal lures, thread hijacks) come from properly
authenticated domains with little for rules to catch.

Twenty phishing emails carry a hidden instruction aimed at AI tools (hidden
with `display:none`, white text, a zero font size, opacity or an HTML comment).
`twins/` holds each of them without the instruction, so its effect can be
measured on otherwise identical emails.

## Caveats

The dataset was written by the same author as the rules, so it shares their
blind spots and flatters them; treat the numbers as a regression baseline and a
way to compare modes, not as a benchmark of real-world accuracy. All mail is in
English and comes from one fictional organisation.
