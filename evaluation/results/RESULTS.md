# Hookline evaluation results

Generated 2026-11-16 12:31 UTC with Hookline 0.1.0. Dataset: 240 emails (120 phishing, 120 benign). Language model: ollama / llama3.1:8b.
The model answered 240 of 240 emails; 0 answers were missing or invalid and fell back to rules.

An email counts as flagged when its verdict is suspicious or malicious. Phishing is the positive class.

## Summary

| Mode | Precision | Recall | F1 | False positive rate | TP | FP | TN | FN | Mean time |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Rules only | 1.000 | 0.617 | 0.763 | 0.000 | 74 | 0 | 120 | 46 | 10 ms |
| AI only | 0.551 | 0.983 | 0.707 | 0.800 | 118 | 96 | 24 | 2 | 127.4 s |
| Combined | 0.701 | 0.842 | 0.765 | 0.358 | 101 | 43 | 77 | 19 | 127.4 s |

## Confusion matrices

**Rules only**

| | Flagged | Not flagged |
| --- | ---: | ---: |
| Phishing | 74 | 46 |
| Benign | 0 | 120 |

**AI only**

| | Flagged | Not flagged |
| --- | ---: | ---: |
| Phishing | 118 | 2 |
| Benign | 96 | 24 |

**Combined**

| | Flagged | Not flagged |
| --- | ---: | ---: |
| Phishing | 101 | 19 |
| Benign | 43 | 77 |

## Flag rate by category

For phishing categories this is the detection rate; for benign ones, the false positive rate.

| Category | Rules only | AI only | Combined |
| --- | ---: | ---: | ---: |
| benign/hr_announcement | 0% | 100% | 0% |
| benign/internal_memo | 0% | 20% | 0% |
| benign/it_notice | 0% | 100% | 100% |
| benign/meeting_invite | 0% | 100% | 0% |
| benign/newsletter | 0% | 100% | 100% |
| benign/password_reset | 0% | 100% | 90% |
| benign/receipt | 0% | 100% | 0% |
| benign/reply_thread | 0% | 0% | 0% |
| benign/shipping_notice | 0% | 100% | 50% |
| benign/vendor_invoice | 0% | 100% | 0% |
| phishing/bec_payment | 58% | 100% | 75% |
| phishing/credential_link | 100% | 100% | 100% |
| phishing/gift_card | 100% | 100% | 100% |
| phishing/homoglyph_sender | 100% | 100% | 100% |
| phishing/html_attachment | 38% | 100% | 100% |
| phishing/invoice_fraud | 75% | 100% | 100% |
| phishing/lookalike_sender | 67% | 100% | 100% |
| phishing/low_signal | 25% | 83% | 25% |
| phishing/malware_attachment | 92% | 100% | 100% |
| phishing/scam | 0% | 100% | 67% |
| phishing/shortener_lure | 67% | 100% | 100% |
| phishing/thread_hijack | 50% | 100% | 75% |

## Prompt injection

20 phishing emails carry a hidden instruction aimed at AI tools; each has an identical twin without it.

- The `prompt_injection` check fired on 15 of 20 injected emails.
- Rules only: 17 of 20 flagged with the injection, 11 without it.
- AI only: 20 of 20 flagged with the injection, 19 without it.
- Combined: 19 of 20 flagged with the injection, 15 without it.
- Mean AI likelihood: 90.8 with the injection, 82.8 without.
- The injection changed the model's answer in 6 of 20 pairs where it answered both (likelihood moved by 10 or more, or a different attack type), and lowered the likelihood by 10 or more in 0.

## Misclassified emails

| Email | Label | Wrong in | Rules score | Main rule findings |
| --- | --- | --- | ---: | --- |
| b005-internal-memo | benign | AI only | 0 | none |
| b010-internal-memo | benign | AI only | 0 | none |
| b011-internal-memo | benign | AI only | 0 | none |
| b012-internal-memo | benign | AI only | 0 | none |
| b021-meeting-invite | benign | AI only | 0 | none |
| b022-meeting-invite | benign | AI only | 0 | none |
| b023-meeting-invite | benign | AI only | 0 | none |
| b024-meeting-invite | benign | AI only | 0 | none |
| b025-meeting-invite | benign | AI only | 0 | none |
| b026-meeting-invite | benign | AI only | 0 | none |
| b027-meeting-invite | benign | AI only | 0 | none |
| b028-meeting-invite | benign | AI only | 0 | none |
| b029-meeting-invite | benign | AI only | 0 | none |
| b030-meeting-invite | benign | AI only | 0 | none |
| b031-newsletter | benign | AI only, Combined | 15 | return_path_mismatch, obfuscated_url, hidden_text |
| b032-newsletter | benign | AI only, Combined | 15 | return_path_mismatch, obfuscated_url, hidden_text |
| b033-newsletter | benign | AI only, Combined | 20 | return_path_mismatch, obfuscated_url, urgency_language |
| b034-newsletter | benign | AI only, Combined | 15 | return_path_mismatch, obfuscated_url, hidden_text |
| b035-newsletter | benign | AI only, Combined | 15 | return_path_mismatch, obfuscated_url, hidden_text |
| b036-newsletter | benign | AI only, Combined | 15 | return_path_mismatch, obfuscated_url, hidden_text |
| b037-newsletter | benign | AI only, Combined | 15 | return_path_mismatch, obfuscated_url, hidden_text |
| b038-newsletter | benign | AI only, Combined | 15 | return_path_mismatch, obfuscated_url, hidden_text |
| b039-newsletter | benign | AI only, Combined | 15 | return_path_mismatch, obfuscated_url, hidden_text |
| b040-newsletter | benign | AI only, Combined | 15 | return_path_mismatch, obfuscated_url, hidden_text |
| b041-newsletter | benign | AI only, Combined | 15 | return_path_mismatch, obfuscated_url, hidden_text |
| b042-newsletter | benign | AI only, Combined | 15 | return_path_mismatch, obfuscated_url, hidden_text |
| b043-newsletter | benign | AI only, Combined | 15 | return_path_mismatch, obfuscated_url, hidden_text |
| b044-newsletter | benign | AI only, Combined | 15 | return_path_mismatch, obfuscated_url, hidden_text |
| b045-newsletter | benign | AI only, Combined | 20 | return_path_mismatch, obfuscated_url, urgency_language |
| b046-newsletter | benign | AI only, Combined | 15 | return_path_mismatch, obfuscated_url, hidden_text |
| b047-newsletter | benign | AI only, Combined | 15 | return_path_mismatch, obfuscated_url, hidden_text |
| b048-newsletter | benign | AI only, Combined | 20 | return_path_mismatch, obfuscated_url, urgency_language |
| b049-newsletter | benign | AI only, Combined | 15 | return_path_mismatch, obfuscated_url, hidden_text |
| b050-newsletter | benign | AI only, Combined | 15 | return_path_mismatch, obfuscated_url, hidden_text |
| b051-vendor-invoice | benign | AI only | 0 | none |
| b052-vendor-invoice | benign | AI only | 5 | urgency_language |
| b053-vendor-invoice | benign | AI only | 5 | urgency_language |
| b054-vendor-invoice | benign | AI only | 5 | urgency_language |
| b055-vendor-invoice | benign | AI only | 5 | urgency_language |
| b056-vendor-invoice | benign | AI only | 5 | urgency_language |
| and 102 more | | | | |
