"""Run the analyzer over a labelled dataset and score the three analysis modes.

Each email is analysed once. With a language model available, that single run
yields all three verdicts: rules only (the indicators alone), AI only (the
model's likelihood alone) and combined (what Hookline reports). An email counts
as flagged when its verdict is suspicious or malicious. Threat intelligence is
always off, so results are reproducible offline.

For emails with a hidden prompt injection, the twin without it is analysed
too, which isolates what the injection itself changes.
"""

import csv
from collections import defaultdict
from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from pathlib import Path

from pydantic import AwareDatetime, Field

from hookline import __version__
from hookline.ai import Assessor
from hookline.config import Settings
from hookline.evaluation.dataset import Entry
from hookline.evaluation.metrics import Confusion, confusion, mean, percentile
from hookline.models.ai import AIAssessment, AIStatus
from hookline.models.base import FrozenModel
from hookline.models.indicator import IndicatorType
from hookline.models.report import Report
from hookline.models.verdict import AnalysisMode, Verdict, VerdictLabel
from hookline.pipeline import Analyzer
from hookline.scoring import score_verdict

MODES = (AnalysisMode.RULES_ONLY, AnalysisMode.AI_ONLY, AnalysisMode.COMBINED)
# A likelihood shift smaller than this is treated as noise between two runs.
LIKELIHOOD_CHANGE = 10


class Prediction(FrozenModel):
    """One mode's verdict on one email."""

    sample_id: str
    label: str
    category: str
    mode: AnalysisMode
    flagged: bool
    verdict: VerdictLabel
    score: float
    duration_ms: float = Field(ge=0)
    top_findings: tuple[str, ...] = ()


class ModeResult(FrozenModel):
    """Metrics for one analysis mode."""

    mode: AnalysisMode
    tp: int
    fp: int
    tn: int
    fn: int
    precision: float
    recall: float
    f1: float
    false_positive_rate: float
    accuracy: float
    mean_ms: float
    p95_ms: float
    category_flag_rates: dict[str, float]


class InjectionResult(FrozenModel):
    """What hidden prompt injections changed, measured on email pairs."""

    pairs: int
    detected_by_rules: int
    flagged_with_injection: dict[AnalysisMode, int]
    flagged_without_injection: dict[AnalysisMode, int]
    ai_pairs_answered: int = Field(
        default=0, description="Pairs where the model answered for both emails."
    )
    mean_ai_likelihood_with_injection: float | None = None
    mean_ai_likelihood_without_injection: float | None = None
    ai_answer_changed: int | None = Field(
        default=None,
        description="Pairs where the likelihood moved by 10+ or the attack type differed.",
    )
    ai_likelihood_lowered: int | None = Field(
        default=None, description="Pairs where the injection lowered the likelihood by 10+."
    )


class EvaluationResult(FrozenModel):
    """Everything one evaluation run measured."""

    generated_at: AwareDatetime
    tool_version: str = __version__
    emails: int
    phishing: int
    benign: int
    ai_provider: str | None = None
    ai_model: str | None = None
    ai_answers: int = 0
    ai_failures: int = 0
    modes: tuple[ModeResult, ...]
    modes_not_run: tuple[AnalysisMode, ...] = ()
    injection: InjectionResult
    predictions: tuple[Prediction, ...]


def run_evaluation(
    entries: Sequence[Entry],
    settings: Settings,
    *,
    assessor: Assessor | None = None,
    on_progress: Callable[[int, int], None] | None = None,
) -> EvaluationResult:
    """Analyse every email and compute the metrics for each mode that can run."""
    offline = settings.model_copy(
        update={
            "ai_enabled": assessor is not None,
            "threat_intel": settings.threat_intel.model_copy(update={"enabled": False}),
        }
    )
    predictions: list[Prediction] = []
    twin_predictions: list[Prediction] = []
    pairs: dict[str, tuple[AIAssessment | None, AIAssessment | None]] = {}
    detected = 0
    answers = failures = 0
    with Analyzer(offline, assessor=assessor) as analyzer:
        for number, entry in enumerate(entries, start=1):
            report = analyzer.analyze_bytes(entry.path.read_bytes(), source_file=entry.path.name)
            answered = report.ai.assessment is not None
            answers += answered
            failures += assessor is not None and not answered
            predictions += _predictions(entry, report, settings)
            if entry.twin_path is not None:
                twin = analyzer.analyze_bytes(entry.twin_path.read_bytes())
                twin_predictions += _predictions(entry, twin, settings)
                detected += any(
                    item.type is IndicatorType.PROMPT_INJECTION for item in report.indicators
                )
                pairs[entry.sample_id] = (report.ai.assessment, twin.ai.assessment)
            if on_progress is not None:
                on_progress(number, len(entries))

    ran = MODES if assessor is not None else (AnalysisMode.RULES_ONLY,)
    phishing = sum(entry.is_phishing for entry in entries)
    return EvaluationResult(
        generated_at=datetime.now(UTC),
        emails=len(entries),
        phishing=phishing,
        benign=len(entries) - phishing,
        ai_provider=assessor.model.name if assessor else None,
        ai_model=assessor.model.model if assessor else None,
        ai_answers=answers,
        ai_failures=failures,
        modes=tuple(_mode_result(mode, predictions) for mode in ran),
        modes_not_run=tuple(mode for mode in MODES if mode not in ran),
        injection=_injection_result(
            [p for p in predictions if p.sample_id in pairs],
            twin_predictions,
            pairs,
            detected,
            ran,
        ),
        predictions=tuple(predictions),
    )


def _predictions(entry: Entry, report: Report, settings: Settings) -> list[Prediction]:
    ai_ms = report.ai.duration_ms
    rules_ms = max(report.duration_ms - ai_ms, 0.0)
    verdicts: list[tuple[AnalysisMode, Verdict, float]] = [
        (AnalysisMode.RULES_ONLY, score_verdict(report.indicators, settings.scoring), rules_ms)
    ]
    assessment = report.ai.assessment
    if assessment is not None:
        ai_only = score_verdict(
            report.indicators, settings.scoring, assessment, mode=AnalysisMode.AI_ONLY
        )
        verdicts.append((AnalysisMode.AI_ONLY, ai_only, ai_ms))
        verdicts.append((AnalysisMode.COMBINED, report.verdict, report.duration_ms))
    elif report.ai.status is not AIStatus.DISABLED:
        # No answer: AI-only cannot flag anything, combined falls back to the rules.
        unflagged = Verdict(
            label=VerdictLabel.LIKELY_SAFE,
            score=0,
            mode=AnalysisMode.AI_ONLY,
            suspicious_threshold=settings.scoring.suspicious_threshold,
            malicious_threshold=settings.scoring.malicious_threshold,
            summary="No answer from the model.",
        )
        verdicts.append((AnalysisMode.AI_ONLY, unflagged, ai_ms))
        verdicts.append((AnalysisMode.COMBINED, report.verdict, report.duration_ms))
    findings = tuple(contribution.label for contribution in verdicts[0][1].contributions[:3])
    return [
        Prediction(
            sample_id=entry.sample_id,
            label=entry.label,
            category=entry.category,
            mode=mode,
            flagged=verdict.label is not VerdictLabel.LIKELY_SAFE,
            verdict=verdict.label,
            score=verdict.score,
            duration_ms=duration,
            top_findings=findings,
        )
        for mode, verdict, duration in verdicts
    ]


def _mode_result(mode: AnalysisMode, predictions: Sequence[Prediction]) -> ModeResult:
    selected = [p for p in predictions if p.mode is mode]
    matrix: Confusion = confusion((p.label == "phishing", p.flagged) for p in selected)
    by_category: defaultdict[str, list[bool]] = defaultdict(list)
    for prediction in selected:
        by_category[f"{prediction.label}/{prediction.category}"].append(prediction.flagged)
    durations = [p.duration_ms for p in selected]
    return ModeResult(
        mode=mode,
        tp=matrix.tp,
        fp=matrix.fp,
        tn=matrix.tn,
        fn=matrix.fn,
        precision=matrix.precision,
        recall=matrix.recall,
        f1=matrix.f1,
        false_positive_rate=matrix.false_positive_rate,
        accuracy=matrix.accuracy,
        mean_ms=mean(durations),
        p95_ms=percentile(durations, 0.95),
        category_flag_rates={
            category: sum(flags) / len(flags) for category, flags in sorted(by_category.items())
        },
    )


def _injection_result(
    injected: Sequence[Prediction],
    twins: Sequence[Prediction],
    pairs: dict[str, tuple[AIAssessment | None, AIAssessment | None]],
    detected: int,
    modes: Sequence[AnalysisMode],
) -> InjectionResult:
    def flagged(predictions: Sequence[Prediction], mode: AnalysisMode) -> int:
        return sum(p.flagged for p in predictions if p.mode is mode)

    answered = [
        (with_, without)
        for with_, without in pairs.values()
        if with_ is not None and without is not None
    ]
    shifts = [
        without.phishing_likelihood - with_.phishing_likelihood for with_, without in answered
    ]
    changed = sum(
        abs(shift) >= LIKELIHOOD_CHANGE or with_.attack_type is not without.attack_type
        for shift, (with_, without) in zip(shifts, answered, strict=True)
    )
    return InjectionResult(
        pairs=len(pairs),
        detected_by_rules=detected,
        flagged_with_injection={mode: flagged(injected, mode) for mode in modes},
        flagged_without_injection={mode: flagged(twins, mode) for mode in modes},
        ai_pairs_answered=len(answered),
        mean_ai_likelihood_with_injection=(
            mean([float(a.phishing_likelihood) for a, _ in answered]) if answered else None
        ),
        mean_ai_likelihood_without_injection=(
            mean([float(b.phishing_likelihood) for _, b in answered]) if answered else None
        ),
        ai_answer_changed=changed if answered else None,
        ai_likelihood_lowered=(
            sum(shift >= LIKELIHOOD_CHANGE for shift in shifts) if answered else None
        ),
    )


def probe_assessor(assessor: Assessor, entry: Entry) -> str | None:
    """Try the model on one email first; returns why it is unusable, or None if it answered.

    Saves analysing a whole dataset against a model that is not running.
    """
    from hookline.parsing import parse_email

    run = assessor.assess(parse_email(entry.path.read_bytes()), ())
    if run.status in {AIStatus.UNAVAILABLE, AIStatus.FAILED}:
        return run.error or run.status.value
    return None


def write_predictions(result: EvaluationResult, path: Path) -> None:
    """One CSV row per email and mode, for inspecting individual verdicts."""
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle, lineterminator="\n")
        writer.writerow(
            ["id", "label", "category", "mode", "flagged", "verdict", "score", "ms", "findings"]
        )
        for p in result.predictions:
            writer.writerow(
                [
                    p.sample_id,
                    p.label,
                    p.category,
                    p.mode.value,
                    int(p.flagged),
                    p.verdict.value,
                    f"{p.score:g}",
                    f"{p.duration_ms:.1f}",
                    ";".join(p.top_findings),
                ]
            )
