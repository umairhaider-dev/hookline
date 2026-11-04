"""Data models shared by every stage of the analysis."""

from hookline.models.ai import AIAssessment, AIRun, AIStatus, AttackType
from hookline.models.email import (
    Attachment,
    AuthResult,
    EmailAddress,
    Header,
    Link,
    LinkOrigin,
    ParsedEmail,
    ReceivedHop,
)
from hookline.models.indicator import Indicator, IndicatorSource, IndicatorType, Severity
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
    "IOCSet",
    "Indicator",
    "IndicatorSource",
    "IndicatorType",
    "Link",
    "LinkOrigin",
    "MitreTechnique",
    "ParsedEmail",
    "ReceivedHop",
    "Report",
    "ScoreContribution",
    "Severity",
    "Verdict",
    "VerdictLabel",
]
