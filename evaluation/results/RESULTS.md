# Hookline evaluation results

Generated 2026-11-05 05:29 UTC with Hookline 0.1.0. Dataset: 240 emails (120 phishing, 120 benign). Language model: none (rules only).

An email counts as flagged when its verdict is suspicious or malicious. Phishing is the positive class.

## Summary

| Mode | Precision | Recall | F1 | False positive rate | TP | FP | TN | FN | Mean time |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Rules only | 1.000 | 0.700 | 0.824 | 0.000 | 84 | 0 | 120 | 36 | 7 ms |
| AI only | not run: no language model was available | | | | | | | | |
| Combined | not run: no language model was available | | | | | | | | |

## Confusion matrices

**Rules only**

| | Flagged | Not flagged |
| --- | ---: | ---: |
| Phishing | 84 | 36 |
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
| phishing/html_attachment | 12% |
| phishing/invoice_fraud | 90% |
| phishing/lookalike_sender | 50% |
| phishing/low_signal | 25% |
| phishing/malware_attachment | 83% |
| phishing/shortener_lure | 83% |
| phishing/thread_hijack | 58% |

## Prompt injection

20 phishing emails carry a hidden instruction aimed at AI tools; each has an identical twin without it.

- The `prompt_injection` check fired on 16 of 20 injected emails.
- Rules only: 20 of 20 flagged with the injection, 12 without it.

## Misclassified emails

| Email | Label | Wrong in | Rules score | Main rule findings |
| --- | --- | --- | ---: | --- |
| p139-lookalike-sender | phishing | Rules only | 15 | lookalike_domain |
| p143-lookalike-sender | phishing | Rules only | 30 | display_name_spoofing, lookalike_domain |
| p144-lookalike-sender | phishing | Rules only | 15 | lookalike_domain |
| p147-lookalike-sender | phishing | Rules only | 30 | lookalike_domain |
| p149-lookalike-sender | phishing | Rules only | 30 | lookalike_domain, credential_login_path |
| p150-lookalike-sender | phishing | Rules only | 30 | lookalike_domain, credential_login_path |
| p159-html-attachment | phishing | Rules only | 15 | risky_attachment |
| p160-html-attachment | phishing | Rules only | 15 | risky_attachment |
| p161-html-attachment | phishing | Rules only | 15 | risky_attachment |
| p162-html-attachment | phishing | Rules only | 20 | risky_attachment, spf_fail |
| p163-html-attachment | phishing | Rules only | 15 | risky_attachment |
| p164-html-attachment | phishing | Rules only | 20 | risky_attachment, auth_results_missing |
| p166-html-attachment | phishing | Rules only | 20 | risky_attachment, auth_results_missing |
| p170-malware-attachment | phishing | Rules only | 30 | risky_attachment |
| p177-malware-attachment | phishing | Rules only | 30 | risky_attachment |
| p179-bec-payment | phishing | Rules only | 0 | none |
| p181-bec-payment | phishing | Rules only | 0 | none |
| p184-bec-payment | phishing | Rules only | 15 | payment_request |
| p188-bec-payment | phishing | Rules only | 5 | urgency_language |
| p189-bec-payment | phishing | Rules only | 15 | payment_request |
| p210-invoice-fraud | phishing | Rules only | 30 | lookalike_domain, payment_request |
| p215-shortener-lure | phishing | Rules only | 20 | url_shortener, urgency_language |
| p217-low-signal | phishing | Rules only | 0 | none |
| p218-low-signal | phishing | Rules only | 0 | none |
| p219-low-signal | phishing | Rules only | 0 | none |
| p220-low-signal | phishing | Rules only | 0 | none |
| p222-low-signal | phishing | Rules only | 0 | none |
| p224-low-signal | phishing | Rules only | 0 | none |
| p225-low-signal | phishing | Rules only | 0 | none |
| p226-low-signal | phishing | Rules only | 0 | none |
| p227-low-signal | phishing | Rules only | 0 | none |
| p229-thread-hijack | phishing | Rules only | 0 | none |
| p236-thread-hijack | phishing | Rules only | 20 | payment_request, spf_fail |
| p237-thread-hijack | phishing | Rules only | 0 | none |
| p239-thread-hijack | phishing | Rules only | 20 | payment_request, spf_fail |
| p240-thread-hijack | phishing | Rules only | 15 | payment_request |
