"""Data models shared by every stage of the analysis."""

from hookline.models.ai import AIAssessment, AIRun, AIStatus, AttackType
from hookline.models.email import (
    Attachment,
    AuthResult,
    EmailAddress,
    Header,
    HiddenText,
    Link,
    LinkOrigin,
    ParsedEmail,
    ReceivedHop,
)
from hookline.models.indicator import Indicator, IndicatorSource, IndicatorType, Severity
from hookline.models.intel import (
    IntelResult,
    IntelRun,
    IntelStatus,
    IntelVerdict,
    Observable,
    ObservableKind,
)
from hookline.models.report import IOCSet, MitreTechnique, Report
from hookline.models.verdict import (
    AnalysisMode,
    ContributionSource,
    ScoreContribution,
    Verdict,
    VerdictLabel,
)

__all__ = [
    "AIAssessment",
    "AIRun",
    "AIStatus",
    "AnalysisMode",
    "Attachment",
    "AttackType",
    "AuthResult",
    "ContributionSource",
    "EmailAddress",
    "Header",
    "HiddenText",
    "IOCSet",
    "Indicator",
    "IndicatorSource",
    "IndicatorType",
    "IntelResult",
    "IntelRun",
    "IntelStatus",
    "IntelVerdict",
    "Link",
    "LinkOrigin",
    "MitreTechnique",
    "Observable",
    "ObservableKind",
    "ParsedEmail",
    "ReceivedHop",
    "Report",
    "ScoreContribution",
    "Severity",
    "Verdict",
    "VerdictLabel",
]
