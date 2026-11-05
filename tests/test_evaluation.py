import csv
import re
import tomllib
from collections import Counter
from email import message_from_bytes, policy
from functools import lru_cache
from pathlib import Path

import pytest

from hookline.ai import ModelRequest
from hookline.config import CheckSettings, Settings, load_settings
from hookline.domains import parse_ip, registrable_domain
from hookline.errors import InputError
from hookline.evaluation import (
    PROTECTED_DOMAINS,
    Sample,
    confusion,
    generate,
    load_dataset,
    render_markdown,
    run_evaluation,
    summary_table,
    write_dataset,
)
from hookline.evaluation.dataset import LABELS_FILE
from hookline.evaluation.generator import (
    BENIGN,
    FREEMAIL,
    INJECTED_SAMPLES,
    PHISHING,
    SHORTENER,
)
from hookline.evaluation.metrics import Confusion, mean, percentile
from hookline.evaluation.runner import probe_assessor, write_predictions
from hookline.models import AIStatus, AnalysisMode, IndicatorType
from hookline.parsing import parse_email
from hookline.pipeline import Analyzer
from hookline.urls import parse_url
from tests.ai_helpers import FakeModel, answer, make_assessor
from tests.factories import PROJECT_ROOT


@lru_cache(maxsize=1)
def dataset() -> tuple[Sample, ...]:
    return tuple(generate(7))


def eval_settings() -> Settings:
    return Settings(
        ai_enabled=False,
        checks=CheckSettings(
            protected_domains=PROTECTED_DOMAINS,
            freemail_domains=FREEMAIL,
            url_shorteners=(SHORTENER,),
        ),
    )


# --- generator ----------------------------------------------------------------


def test_dataset_size_labels_and_categories() -> None:
    samples = dataset()
    assert len(samples) == 240
    assert Counter(sample.label for sample in samples) == {"benign": 120, "phishing": 120}
    expected = {category: count for category, _, count, _ in (*BENIGN, *PHISHING)}
    assert Counter(sample.category for sample in samples) == expected
    assert len({sample.sample_id for sample in samples}) == 240


def test_generation_is_reproducible() -> None:
    assert tuple(generate(7)) == dataset()
    assert tuple(generate(8)) != dataset()


def test_only_reserved_domains_and_documentation_addresses() -> None:
    allowed_suffixes = (".test", ".example.org", "example.org")
    for sample in dataset():
        email = parse_email(sample.raw)
        assert email.defects == (), sample.sample_id
        addresses = [email.from_address, *email.to, *email.cc, *email.reply_to]
        for address in addresses:
            assert address is not None
            assert address.domain.endswith(allowed_suffixes), (sample.sample_id, address)
        for link in email.links:
            url = parse_url(link.url)
            assert url is not None
            if url.ip is None:
                assert url.host.endswith(allowed_suffixes), (sample.sample_id, link.url)
        for hop in email.received:
            assert hop.from_ip is not None
            assert str(hop.from_ip).startswith(("192.0.2.", "198.51.100.", "203.0.113."))


def test_injections_and_their_twins() -> None:
    injected = [sample for sample in dataset() if sample.injection]
    assert len(injected) == INJECTED_SAMPLES
    for sample in injected:
        assert sample.label == "phishing"
        assert sample.twin is not None
        with_injection, without = parse_email(sample.raw), parse_email(sample.twin)
        assert with_injection.html_text == without.html_text
        assert with_injection.subject == without.subject
        assert len(with_injection.hidden_text) == len(without.hidden_text) + 1
    assert all(sample.twin is None for sample in dataset() if not sample.injection)


def test_attachments_are_inert() -> None:
    markers = 0
    for sample in dataset():
        message = message_from_bytes(sample.raw, policy=policy.default)
        for part in message.walk():
            if part.get_filename():
                payload = part.get_payload(decode=True)
                assert isinstance(payload, bytes)
                assert len(payload) < 40_000
                markers += b"Hookline test sample" in payload or b"inert" in payload
    assert markers > 0


def test_eval_config_matches_the_generator() -> None:
    path = PROJECT_ROOT / "evaluation" / "hookline-eval.toml"
    checks = tomllib.loads(path.read_text(encoding="utf-8"))["checks"]
    assert tuple(checks["protected_domains"]) == PROTECTED_DOMAINS
    assert tuple(checks["freemail_domains"]) == FREEMAIL
    assert checks["url_shorteners"] == [SHORTENER]
    assert load_settings(path).checks.trusted_authserv_ids == ("mx1.larkspur.test",)


def test_reserved_domains_are_not_on_the_public_suffix_list() -> None:
    # Their registrable domain is the label before .test, so lookalike checks work.
    assert registrable_domain("mail.quillon-payroll.test") == "quillon-payroll.test"
    assert parse_ip("192.0.2.10") is not None


# --- dataset files ------------------------------------------------------------


def _injection_detected(sample: Sample) -> bool:
    report = Analyzer(eval_settings()).analyze_bytes(sample.raw)
    return any(item.type is IndicatorType.PROMPT_INJECTION for item in report.indicators)


def small_dataset(directory: Path) -> Path:
    """Two benign emails, two plain phishing emails and two detected injections."""
    samples = dataset()
    benign = [sample for sample in samples if sample.label == "benign"][:2]
    plain = [sample for sample in samples if sample.label == "phishing" and not sample.injection]
    injected = [sample for sample in samples if sample.injection and _injection_detected(sample)]
    write_dataset([*benign, *plain[:2], *injected[:2]], directory)
    return directory


def test_write_and_load_round_trip(tmp_path: Path) -> None:
    entries = load_dataset(small_dataset(tmp_path))
    assert len(entries) == 6
    assert sum(entry.is_phishing for entry in entries) == 4
    injected = [entry for entry in entries if entry.injection]
    assert len(injected) == 2
    assert all(entry.twin_path is not None and entry.twin_path.is_file() for entry in injected)
    with (tmp_path / LABELS_FILE).open(encoding="utf-8") as handle:
        assert next(csv.reader(handle))[0] == "id"


@pytest.mark.parametrize(
    ("content", "message"),
    [
        (None, "No labels.csv"),
        ("id,label\n", "lacks the column"),
        ("id,label,category,difficulty,file,injection,twin_file\n", "lists no emails"),
        (
            "id,label,category,difficulty,file,injection,twin_file\nx,spam,c,easy,e.eml,,\n",
            "unknown label",
        ),
        (
            "id,label,category,difficulty,file,injection,twin_file\nx,benign,c,easy,e.eml,,\n",
            "does not exist",
        ),
    ],
)
def test_load_errors(tmp_path: Path, content: str | None, message: str) -> None:
    if content is not None:
        (tmp_path / LABELS_FILE).write_text(content, encoding="utf-8")
    with pytest.raises(InputError, match=message):
        load_dataset(tmp_path)


def test_missing_twin_is_an_error(tmp_path: Path) -> None:
    (tmp_path / "e.eml").write_bytes(b"Subject: x\r\n\r\nbody")
    (tmp_path / LABELS_FILE).write_text(
        "id,label,category,difficulty,file,injection,twin_file\n"
        "x,phishing,c,easy,e.eml,display:none,twins/x.eml\n",
        encoding="utf-8",
    )
    with pytest.raises(InputError, match="twins"):
        load_dataset(tmp_path)


# --- metrics ------------------------------------------------------------------


def test_confusion_and_metrics() -> None:
    outcomes = [(True, True)] * 8 + [(True, False)] * 2 + [(False, True)] + [(False, False)] * 9
    matrix = confusion(outcomes)
    assert matrix == Confusion(tp=8, fp=1, tn=9, fn=2)
    assert matrix.total == 20
    assert matrix.precision == pytest.approx(8 / 9)
    assert matrix.recall == pytest.approx(0.8)
    assert matrix.f1 == pytest.approx(2 * (8 / 9) * 0.8 / (8 / 9 + 0.8))
    assert matrix.false_positive_rate == pytest.approx(0.1)
    assert matrix.accuracy == pytest.approx(17 / 20)


def test_metrics_without_data() -> None:
    empty = Confusion()
    assert (empty.precision, empty.recall, empty.f1, empty.false_positive_rate) == (0, 0, 0, 0)
    assert empty.accuracy == 0
    assert percentile([], 0.95) == 0
    assert mean([]) == 0
    assert percentile([5.0, 1.0, 3.0, 2.0, 4.0], 0.95) == 5.0
    assert percentile([5.0, 1.0], 0.0) == 1.0


# --- runner and summary -------------------------------------------------------


class InjectionSensitiveModel(FakeModel):
    """Phishing-sure unless the prompt says an injection was found, to simulate being fooled."""

    def complete(self, request: ModelRequest) -> str:
        self.requests.append(request)
        fooled = '"type": "prompt_injection"' in request.turns[-1].text
        return answer(phishing_likelihood=20 if fooled else 85)


def test_rules_only_run(tmp_path: Path) -> None:
    entries = load_dataset(small_dataset(tmp_path))
    result = run_evaluation(entries, eval_settings())
    assert [mode.mode for mode in result.modes] == [AnalysisMode.RULES_ONLY]
    assert result.modes_not_run == (AnalysisMode.AI_ONLY, AnalysisMode.COMBINED)
    assert result.injection.pairs == 2
    assert result.injection.detected_by_rules == 2
    assert result.injection.mean_ai_likelihood_with_injection is None
    markdown = render_markdown(result)
    assert "not run: no language model was available" in markdown
    assert "Language model: none (rules only)" in markdown


def test_run_with_a_model(tmp_path: Path) -> None:
    entries = load_dataset(small_dataset(tmp_path))
    assessor, _ = make_assessor(InjectionSensitiveModel())
    seen: list[tuple[int, int]] = []
    result = run_evaluation(
        entries, eval_settings(), assessor=assessor, on_progress=lambda *step: seen.append(step)
    )
    assert seen[-1] == (6, 6)
    assert [mode.mode for mode in result.modes] == [
        AnalysisMode.RULES_ONLY,
        AnalysisMode.AI_ONLY,
        AnalysisMode.COMBINED,
    ]
    ai_only = result.modes[1]
    assert ai_only.tp + ai_only.fn == 4
    assert ai_only.fp == 2  # the fake model calls every clean email phishing
    combined = result.modes[2]
    rules = result.modes[0]
    assert combined.tp >= rules.tp
    assert result.ai_answers == 6
    assert result.injection.ai_likelihood_lowered == 2
    assert result.injection.mean_ai_likelihood_with_injection == 20
    assert result.injection.mean_ai_likelihood_without_injection == 85
    assert result.injection.flagged_with_injection[AnalysisMode.COMBINED] == 2
    markdown = render_markdown(result)
    assert "| AI only |" in summary_table(result)
    assert "lowered it by 10 or more in 2 pairs" in markdown
    assert "The model answered 6 of 6 emails" in markdown
    target = tmp_path / "predictions.csv"
    write_predictions(result, target)
    with target.open(encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    assert len(rows) == 18
    assert {row["mode"] for row in rows} == {"rules_only", "ai_only", "combined"}


def test_model_failures_count_as_unflagged(tmp_path: Path) -> None:
    from hookline.ai import ModelUnavailableError

    entries = load_dataset(small_dataset(tmp_path))
    assessor, _ = make_assessor(FakeModel([ModelUnavailableError("down")]))
    result = run_evaluation(entries, eval_settings(), assessor=assessor)
    assert result.ai_failures == 6
    assert result.modes[1].tp == 0
    assert result.modes[2].tp == result.modes[0].tp


def test_probe_assessor(tmp_path: Path) -> None:
    from hookline.ai import ModelUnavailableError

    entry = load_dataset(small_dataset(tmp_path))[0]
    working, _ = make_assessor()
    assert probe_assessor(working, entry) is None
    broken, _ = make_assessor(FakeModel([ModelUnavailableError("Ollama is not reachable")]))
    assert probe_assessor(broken, entry) == "Ollama is not reachable"


def test_errors_table_lists_misclassified_emails(tmp_path: Path) -> None:
    entries = load_dataset(small_dataset(tmp_path))
    result = run_evaluation(entries, eval_settings())
    markdown = render_markdown(result)
    wrong = [p for p in result.predictions if p.flagged != (p.label == "phishing")]
    if wrong:
        assert wrong[0].sample_id in markdown
    else:
        assert "## Misclassified emails\n\nNone." in markdown


def test_committed_dataset_matches_the_generator() -> None:
    directory = PROJECT_ROOT / "evaluation" / "dataset"
    entries = load_dataset(directory)
    by_id = {sample.sample_id: sample for sample in dataset()}
    assert len(entries) == len(by_id)
    for entry in entries:
        assert entry.path.read_bytes() == by_id[entry.sample_id].raw, entry.sample_id


def test_committed_results_are_current_for_rules() -> None:
    results = (PROJECT_ROOT / "evaluation" / "results" / "RESULTS.md").read_text(encoding="utf-8")
    entries = load_dataset(PROJECT_ROOT / "evaluation" / "dataset")
    settings = load_settings(PROJECT_ROOT / "evaluation" / "hookline-eval.toml")
    rules = run_evaluation(entries, settings).modes[0]
    row = re.search(r"\| Rules only \| ([\d.]+) \| ([\d.]+) \|", results)
    assert row is not None
    assert (float(row.group(1)), float(row.group(2))) == (
        round(rules.precision, 3),
        round(rules.recall, 3),
    )


def test_analyzer_finds_injections_in_the_dataset() -> None:
    analyzer = Analyzer(eval_settings())
    injected = [sample for sample in dataset() if sample.injection]
    found = [
        any(
            i.type is IndicatorType.PROMPT_INJECTION
            for i in analyzer.analyze_bytes(s.raw).indicators
        )
        for s in injected
    ]
    assert sum(found) >= len(found) // 2
    assert AIStatus.DISABLED.value == "disabled"
