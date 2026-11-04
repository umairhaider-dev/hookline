import re

import pytest
from pydantic import ValidationError

from hookline.models import Indicator, IndicatorSource, IndicatorType, Severity
from hookline.models.indicator import MAX_VALUE_LENGTH
from tests.factories import make_indicator


def test_id_ignores_evidence_wording() -> None:
    assert make_indicator().id == make_indicator(evidence="Different wording.").id


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("value", "someone@other.test"),
        ("type", IndicatorType.RETURN_PATH_MISMATCH),
        ("source", IndicatorSource.DOMAINS),
    ],
)
def test_id_changes_with_identity_fields(field: str, value: object) -> None:
    assert make_indicator(**{field: value}).id != make_indicator().id


def test_id_is_short_hex() -> None:
    assert re.fullmatch(r"[0-9a-f]{12}", make_indicator().id)


def test_indicators_are_immutable() -> None:
    indicator = make_indicator()
    with pytest.raises(ValidationError, match="frozen"):
        indicator.severity = Severity.LOW  # type: ignore[misc]


def test_json_round_trip_keeps_id() -> None:
    original = make_indicator()
    data = original.model_dump(mode="json")
    assert data["id"] == original.id
    assert Indicator.model_validate(data) == original
    assert Indicator.model_validate_json(original.model_dump_json()) == original


@pytest.mark.parametrize("field", ["value", "evidence"])
def test_empty_text_is_rejected(field: str) -> None:
    with pytest.raises(ValidationError):
        make_indicator(**{field: ""})


def test_unknown_fields_are_rejected() -> None:
    with pytest.raises(ValidationError, match="confidence"):
        make_indicator(confidence=0.9)


def test_overlong_value_is_truncated_not_rejected() -> None:
    indicator = make_indicator(value="x" * (MAX_VALUE_LENGTH + 500))
    assert len(indicator.value) == MAX_VALUE_LENGTH
    assert indicator.value.endswith("[truncated]")


def test_value_at_limit_is_kept_whole() -> None:
    value = "x" * MAX_VALUE_LENGTH
    assert make_indicator(value=value).value == value


def test_severity_rank_follows_declaration_order() -> None:
    assert [level.rank for level in Severity] == [0, 1, 2, 3, 4]
    assert Severity.CRITICAL.rank > Severity.HIGH.rank > Severity.INFO.rank
