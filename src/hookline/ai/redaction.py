"""Remove personal data from text before it is sent to a cloud language model.

What is replaced, and with what:

* email addresses keep their domain (the evidence) but lose the mailbox name:
  ``sam.ortega@larkspur.test`` becomes ``[person 1]@larkspur.test``, with the
  same placeholder every time the same address appears;
* recipients' names from the To and Cc headers become ``[recipient]``;
* phone numbers, card numbers that pass the Luhn check, IBANs and US social
  security numbers (IP addresses and dates are left alone: they are evidence);
* URL query values, which often carry session tokens or the recipient's
  address; the scheme, host and path stay.

Redaction is a best effort. It lowers the amount of personal data that leaves
the machine; it is not a guarantee that none does.
"""

import re

_EMAIL = re.compile(r"(?<![\w.+-])([\w.+-]+)@((?:[\w-]+\.)+[\w-]{2,})", re.UNICODE)
_URL = re.compile(r"https?://[^\s<>\"']+", re.I)
_CARD = re.compile(r"(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)")
_IBAN = re.compile(r"\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,4})?\b")
_SSN = re.compile(r"(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)")
_PHONE = re.compile(r"(?<![\w+])\+?\d[\d ().-]{7,}\d(?!\w)")
_IPV4 = re.compile(r"\d{1,3}(?:\.\d{1,3}){3}")
_ISO_DATE = re.compile(r"\d{4}-\d{2}-\d{2}")
_NAME_SPLIT = re.compile(r"[\s.,_-]+")
MIN_NAME_LENGTH = 3
MIN_PHONE_DIGITS = 9
MAX_PHONE_DIGITS = 15


class Redactor:
    """Redacts one email's text consistently across every part of the prompt."""

    def __init__(self, recipient_names: list[str]) -> None:
        names = {
            token
            for name in recipient_names
            for token in _NAME_SPLIT.split(name)
            if len(token) >= MIN_NAME_LENGTH and token.isalpha()
        }
        self._names = (
            re.compile(
                r"\b(?:" + "|".join(sorted(map(re.escape, names), key=len, reverse=True)) + r")\b",
                re.I,
            )
            if names
            else None
        )
        self._people: dict[str, str] = {}
        self.count = 0

    def redact(self, text: str) -> str:
        """Return ``text`` with personal data replaced by placeholders."""
        text = _URL.sub(self._url, text)
        text = _EMAIL.sub(self._email, text)
        text = _CARD.sub(self._card, text)
        text = self._count(_IBAN, "[IBAN]", text)
        text = self._count(_SSN, "[ID number]", text)
        text = _PHONE.sub(self._phone, text)
        if self._names is not None:
            text = self._count(self._names, "[recipient]", text)
        return text

    def _count(self, pattern: re.Pattern[str], replacement: str, text: str) -> str:
        text, replaced = pattern.subn(replacement, text)
        self.count += replaced
        return text

    def _email(self, match: re.Match[str]) -> str:
        address = match.group(0).lower()
        if address not in self._people:
            self._people[address] = f"[person {len(self._people) + 1}]"
        self.count += 1
        return f"{self._people[address]}@{match.group(2)}"

    def _url(self, match: re.Match[str]) -> str:
        url = match.group(0)
        base, question, query = url.partition("?")
        if not question:
            return url
        fragment = ""
        if "#" in query:
            query, _, fragment = query.partition("#")
            fragment = "#[redacted]" if fragment else ""
        keys = [part.partition("=")[0] for part in query.split("&") if part]
        self.count += 1
        return f"{base}?{'&'.join(f'{key}=[redacted]' for key in keys)}{fragment}"

    def _card(self, match: re.Match[str]) -> str:
        digits = re.sub(r"\D", "", match.group(0))
        if not _luhn_valid(digits):
            return match.group(0)
        self.count += 1
        return "[card number]"

    def _phone(self, match: re.Match[str]) -> str:
        digits = sum(char.isdigit() for char in match.group(0))
        text = match.group(0)
        if (
            not MIN_PHONE_DIGITS <= digits <= MAX_PHONE_DIGITS
            or _ISO_DATE.match(text)
            or _IPV4.fullmatch(text)
        ):
            return text
        self.count += 1
        return "[phone]"


class NoRedaction:
    """Stand-in used when redaction is off, so callers need no branches."""

    count = 0

    def redact(self, text: str) -> str:
        """Return ``text`` unchanged."""
        return text


def _luhn_valid(digits: str) -> bool:
    total = 0
    for position, char in enumerate(reversed(digits)):
        value = int(char)
        if position % 2:
            value *= 2
            if value > 9:
                value -= 9
        total += value
    return total % 10 == 0
