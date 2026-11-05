"""Classification metrics. Phishing is the positive class."""

import math
from collections.abc import Iterable, Sequence
from dataclasses import dataclass


@dataclass(frozen=True)
class Confusion:
    """A 2x2 confusion matrix."""

    tp: int = 0
    fp: int = 0
    tn: int = 0
    fn: int = 0

    @property
    def total(self) -> int:
        """Number of emails counted."""
        return self.tp + self.fp + self.tn + self.fn

    @property
    def precision(self) -> float:
        """Share of flagged emails that really were phishing."""
        return _ratio(self.tp, self.tp + self.fp)

    @property
    def recall(self) -> float:
        """Share of phishing emails that were flagged (detection rate)."""
        return _ratio(self.tp, self.tp + self.fn)

    @property
    def f1(self) -> float:
        """Harmonic mean of precision and recall."""
        return _ratio(2 * self.precision * self.recall, self.precision + self.recall)

    @property
    def false_positive_rate(self) -> float:
        """Share of legitimate emails that were wrongly flagged."""
        return _ratio(self.fp, self.fp + self.tn)

    @property
    def accuracy(self) -> float:
        """Share of all emails classified correctly."""
        return _ratio(self.tp + self.tn, self.total)


def confusion(outcomes: Iterable[tuple[bool, bool]]) -> Confusion:
    """Count ``(is_phishing, flagged)`` pairs into a confusion matrix."""
    tp = fp = tn = fn = 0
    for actual, predicted in outcomes:
        if actual and predicted:
            tp += 1
        elif predicted:
            fp += 1
        elif actual:
            fn += 1
        else:
            tn += 1
    return Confusion(tp=tp, fp=fp, tn=tn, fn=fn)


def percentile(values: Sequence[float], share: float) -> float:
    """The nearest-rank percentile (``share`` between 0 and 1); 0 for no values."""
    if not values:
        return 0.0
    ordered = sorted(values)
    rank = max(math.ceil(share * len(ordered)), 1)
    return ordered[rank - 1]


def mean(values: Sequence[float]) -> float:
    """Arithmetic mean; 0 for no values."""
    return sum(values) / len(values) if values else 0.0


def _ratio(numerator: float, denominator: float) -> float:
    return numerator / denominator if denominator else 0.0
