# Hookline evaluation results

Generated 2026-11-15 14:46 UTC with Hookline 0.1.0. Dataset: 240 emails (120 phishing, 120 benign). Language model: none (rules only).

An email counts as flagged when its verdict is suspicious or malicious. Phishing is the positive class.

## Summary

| Mode | Precision | Recall | F1 | False positive rate | TP | FP | TN | FN | Mean time |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Rules only | 1.000 | 0.617 | 0.763 | 0.000 | 74 | 0 | 120 | 46 | 4 ms |
| AI only | not run: no language model was available | | | | | | | | |
| Combined | not run: no language model was available | | | | | | | | |

## Confusion matrices

**Rules only**

| | Flagged | Not flagged |
| --- | ---: | ---: |
| Phishing | 74 | 46 |
| Benign | 0 | 120 |

## Flag rate by category

For phishing categories this is the detection rate; for benign ones, the false positive rate.

| Category | Rules only |
| --- | ---: |
| benign/hr_announcement | 0% |
| benign/internal_memo | 0% |
| benign/it_notice | 0% |
| benign/meeting_invite | 0% |
| benign/newsletter | 0% |
| benign/password_reset | 0% |
| benign/receipt | 0% |
| benign/reply_thread | 0% |
| benign/shipping_notice | 0% |
| benign/vendor_invoice | 0% |
| phishing/bec_payment | 58% |
| phishing/credential_link | 100% |
| phishing/gift_card | 100% |
| phishing/homoglyph_sender | 100% |
| phishing/html_attachment | 38% |
| phishing/invoice_fraud | 75% |
| phishing/lookalike_sender | 67% |
| phishing/low_signal | 25% |
| phishing/malware_attachment | 92% |
| phishing/scam | 0% |
| phishing/shortener_lure | 67% |
| phishing/thread_hijack | 50% |

## Prompt injection

20 phishing emails carry a hidden instruction aimed at AI tools; each has an identical twin without it.

- The `prompt_injection` check fired on 15 of 20 injected emails.
- Rules only: 17 of 20 flagged with the injection, 11 without it.

## Misclassified emails

| Email | Label | Wrong in | Rules score | Main rule findings |
| --- | --- | --- | ---: | --- |
| p134-lookalike-sender | phishing | Rules only | 15 | lookalike_domain |
| p135-lookalike-sender | phishing | Rules only | 30 | lookalike_domain, credential_login_path |
| p141-lookalike-sender | phishing | Rules only | 30 | lookalike_domain, credential_login_path |
| p143-lookalike-sender | phishing | Rules only | 30 | lookalike_domain, credential_login_path |
| p153-html-attachment | phishing | Rules only | 15 | risky_attachment |
| p154-html-attachment | phishing | Rules only | 20 | risky_attachment, auth_results_missing |
| p155-html-attachment | phishing | Rules only | 15 | risky_attachment |
| p156-html-attachment | phishing | Rules only | 15 | risky_attachment |
| p157-html-attachment | phishing | Rules only | 15 | risky_attachment |
| p166-malware-attachment | phishing | Rules only | 30 | risky_attachment |
| p171-bec-payment | phishing | Rules only | 0 | none |
| p172-bec-payment | phishing | Rules only | 5 | urgency_language |
| p174-bec-payment | phishing | Rules only | 0 | none |
| p176-bec-payment | phishing | Rules only | 15 | payment_request |
| p178-bec-payment | phishing | Rules only | 15 | payment_request |
| p191-scam | phishing | Rules only | 5 | urgency_language |
| p192-scam | phishing | Rules only | 5 | urgency_language |
| p193-scam | phishing | Rules only | 15 | reply_to_mismatch |
| p194-scam | phishing | Rules only | 15 | reply_to_mismatch |
| p195-scam | phishing | Rules only | 15 | reply_to_mismatch |
| p196-scam | phishing | Rules only | 15 | reply_to_mismatch |
| p197-scam | phishing | Rules only | 5 | urgency_language |
| p198-scam | phishing | Rules only | 15 | reply_to_mismatch |
| p199-scam | phishing | Rules only | 5 | urgency_language |
| p200-scam | phishing | Rules only | 15 | reply_to_mismatch |
| p201-scam | phishing | Rules only | 15 | reply_to_mismatch |
| p202-scam | phishing | Rules only | 15 | reply_to_mismatch |
| p204-invoice-fraud | phishing | Rules only | 30 | lookalike_domain, payment_request |
| p210-invoice-fraud | phishing | Rules only | 30 | lookalike_domain, payment_request |
| p212-shortener-lure | phishing | Rules only | 25 | url_shortener, urgency_language, hidden_text |
| p213-shortener-lure | phishing | Rules only | 15 | url_shortener |
| p217-low-signal | phishing | Rules only | 0 | none |
| p218-low-signal | phishing | Rules only | 0 | none |
| p219-low-signal | phishing | Rules only | 0 | none |
| p220-low-signal | phishing | Rules only | 0 | none |
| p221-low-signal | phishing | Rules only | 0 | none |
| p225-low-signal | phishing | Rules only | 0 | none |
| p226-low-signal | phishing | Rules only | 0 | none |
| p227-low-signal | phishing | Rules only | 0 | none |
| p228-low-signal | phishing | Rules only | 0 | none |
| and 6 more | | | | |
