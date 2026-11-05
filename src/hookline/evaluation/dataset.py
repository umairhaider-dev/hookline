"""Read and write the evaluation dataset on disk.

Layout::

    dataset/
      labels.csv          id, label, category, difficulty, file, injection, twin_file
      emails/*.eml        the labelled emails
      twins/*.eml         the injected emails' twins, without the injection
"""

import csv
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from hookline.errors import InputError
from hookline.evaluation.generator import Sample

LABELS_FILE = "labels.csv"
EMAILS_DIR = "emails"
TWINS_DIR = "twins"
COLUMNS = ("id", "label", "category", "difficulty", "file", "injection", "twin_file")
LABELS = frozenset({"phishing", "benign"})


@dataclass(frozen=True)
class Entry:
    """One labelled email in a dataset on disk."""

    sample_id: str
    label: str
    category: str
    difficulty: str
    path: Path
    injection: str | None = None
    twin_path: Path | None = None

    @property
    def is_phishing(self) -> bool:
        """Whether the email is labelled as phishing (the positive class)."""
        return self.label == "phishing"


def write_dataset(samples: Sequence[Sample], directory: Path) -> None:
    """Write ``samples`` and their labels under ``directory``."""
    emails = directory / EMAILS_DIR
    twins = directory / TWINS_DIR
    emails.mkdir(parents=True, exist_ok=True)
    twins.mkdir(parents=True, exist_ok=True)
    rows = []
    for sample in samples:
        name = f"{sample.sample_id}.eml"
        (emails / name).write_bytes(sample.raw)
        twin_file = ""
        if sample.twin is not None:
            (twins / name).write_bytes(sample.twin)
            twin_file = f"{TWINS_DIR}/{name}"
        rows.append(
            {
                "id": sample.sample_id,
                "label": sample.label,
                "category": sample.category,
                "difficulty": sample.difficulty,
                "file": f"{EMAILS_DIR}/{name}",
                "injection": sample.injection or "",
                "twin_file": twin_file,
            }
        )
    with (directory / LABELS_FILE).open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=COLUMNS, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def load_dataset(directory: Path) -> list[Entry]:
    """Read the labels file of a dataset and check that every email exists.

    Raises:
        InputError: If the labels file is missing or malformed, or an email is missing.
    """
    labels = directory / LABELS_FILE
    if not labels.is_file():
        raise InputError(f"No {LABELS_FILE} in {directory}")
    with labels.open(encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        missing = set(COLUMNS) - set(reader.fieldnames or ())
        if missing:
            raise InputError(f"{labels} lacks the column(s): {', '.join(sorted(missing))}")
        entries = [_entry(row, directory, line) for line, row in enumerate(reader, start=2)]
    if not entries:
        raise InputError(f"{labels} lists no emails")
    return entries


def _entry(row: dict[str, str], directory: Path, line: int) -> Entry:
    if row["label"] not in LABELS:
        raise InputError(f"{LABELS_FILE} line {line}: unknown label {row['label']!r}")
    path = directory / row["file"]
    if not path.is_file():
        raise InputError(f"{LABELS_FILE} line {line}: {path} does not exist")
    twin = directory / row["twin_file"] if row["twin_file"] else None
    if twin is not None and not twin.is_file():
        raise InputError(f"{LABELS_FILE} line {line}: {twin} does not exist")
    return Entry(
        sample_id=row["id"],
        label=row["label"],
        category=row["category"],
        difficulty=row["difficulty"],
        path=path,
        injection=row["injection"] or None,
        twin_path=twin,
    )
