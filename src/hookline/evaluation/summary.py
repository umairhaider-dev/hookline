"""Write evaluation results as Markdown for the README and the results file."""

from collections import defaultdict

from hookline.evaluation.runner import EvaluationResult, ModeResult, Prediction
from hookline.models.verdict import AnalysisMode

MODE_NAMES = {
    AnalysisMode.RULES_ONLY: "Rules only",
    AnalysisMode.AI_ONLY: "AI only",
    AnalysisMode.COMBINED: "Combined",
}
MAX_ERRORS_LISTED = 40


def summary_table(result: EvaluationResult) -> str:
    """The headline metrics table, one row per mode."""
    lines = [
        "| Mode | Precision | Recall | F1 | False positive rate | TP | FP | TN | FN | Mean time |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for mode in result.modes:
        lines.append(
            f"| {MODE_NAMES[mode.mode]} | {mode.precision:.3f} | {mode.recall:.3f} | "
            f"{mode.f1:.3f} | {mode.false_positive_rate:.3f} | {mode.tp} | {mode.fp} | "
            f"{mode.tn} | {mode.fn} | {_duration(mode.mean_ms)} |"
        )
    for missing in result.modes_not_run:
        lines.append(
            f"| {MODE_NAMES[missing]} | not run: no language model was available | | | | | | | | |"
        )
    return "\n".join(lines)


def render_markdown(result: EvaluationResult) -> str:
    """The full results document."""
    model = (
        f"{result.ai_provider} / {result.ai_model}" if result.ai_provider else "none (rules only)"
    )
    parts = [
        "# Hookline evaluation results",
        "",
        f"Generated {result.generated_at:%Y-%m-%d %H:%M} UTC with Hookline {result.tool_version}. "
        f"Dataset: {result.emails} emails ({result.phishing} phishing, {result.benign} benign). "
        f"Language model: {model}.",
    ]
    if result.ai_provider:
        parts.append(
            f"The model answered {result.ai_answers} of {result.emails} emails; "
            f"{result.ai_failures} answers were missing or invalid and fell back to rules."
        )
    parts += [
        "",
        "An email counts as flagged when its verdict is suspicious or malicious. "
        "Phishing is the positive class.",
        "",
        "## Summary",
        "",
        summary_table(result),
        "",
        "## Confusion matrices",
        "",
        *(_confusion(mode) for mode in result.modes),
        "## Flag rate by category",
        "",
        "For phishing categories this is the detection rate; for benign ones, the false "
        "positive rate.",
        "",
        _categories(result),
        "",
        "## Prompt injection",
        "",
        _injection(result),
        "",
        "## Misclassified emails",
        "",
        _errors(result),
    ]
    return "\n".join(parts) + "\n"


def _confusion(mode: ModeResult) -> str:
    return (
        f"**{MODE_NAMES[mode.mode]}**\n\n"
        "| | Flagged | Not flagged |\n| --- | ---: | ---: |\n"
        f"| Phishing | {mode.tp} | {mode.fn} |\n| Benign | {mode.fp} | {mode.tn} |\n"
    )


def _categories(result: EvaluationResult) -> str:
    header = "| Category | " + " | ".join(MODE_NAMES[m.mode] for m in result.modes) + " |"
    lines = [header, "| --- |" + " ---: |" * len(result.modes)]
    categories = result.modes[0].category_flag_rates if result.modes else {}
    for category in categories:
        rates = " | ".join(f"{m.category_flag_rates[category]:.0%}" for m in result.modes)
        lines.append(f"| {category} | {rates} |")
    return "\n".join(lines)


def _injection(result: EvaluationResult) -> str:
    injection = result.injection
    lines = [
        f"{injection.pairs} phishing emails carry a hidden instruction aimed at AI tools; each "
        "has an identical twin without it.",
        "",
        f"- The `prompt_injection` check fired on {injection.detected_by_rules} of "
        f"{injection.pairs} injected emails.",
    ]
    for mode, flagged in injection.flagged_with_injection.items():
        without = injection.flagged_without_injection.get(mode, 0)
        lines.append(
            f"- {MODE_NAMES[mode]}: {flagged} of {injection.pairs} flagged with the injection, "
            f"{without} without it."
        )
    if injection.mean_ai_likelihood_with_injection is not None:
        lines.append(
            f"- Mean AI likelihood: {injection.mean_ai_likelihood_with_injection:.1f} with the "
            f"injection, {injection.mean_ai_likelihood_without_injection:.1f} without; the "
            f"injection lowered it by 10 or more in {injection.ai_likelihood_lowered} pairs."
        )
    return "\n".join(lines)


def _errors(result: EvaluationResult) -> str:
    grouped: defaultdict[str, list[Prediction]] = defaultdict(list)
    for prediction in result.predictions:
        if prediction.flagged != (prediction.label == "phishing"):
            grouped[prediction.sample_id].append(prediction)
    if not grouped:
        return "None."
    lines = [
        "| Email | Label | Wrong in | Rules score | Main rule findings |",
        "| --- | --- | --- | ---: | --- |",
    ]
    for sample_id, wrong in list(grouped.items())[:MAX_ERRORS_LISTED]:
        rules = next(
            (
                p
                for p in result.predictions
                if p.sample_id == sample_id and p.mode is AnalysisMode.RULES_ONLY
            ),
            wrong[0],
        )
        modes = ", ".join(MODE_NAMES[p.mode] for p in wrong)
        findings = ", ".join(rules.top_findings) or "none"
        lines.append(f"| {sample_id} | {wrong[0].label} | {modes} | {rules.score:g} | {findings} |")
    if len(grouped) > MAX_ERRORS_LISTED:
        lines.append(f"| and {len(grouped) - MAX_ERRORS_LISTED} more | | | | |")
    return "\n".join(lines)


def _duration(milliseconds: float) -> str:
    return f"{milliseconds:.0f} ms" if milliseconds < 1000 else f"{milliseconds / 1000:.1f} s"
