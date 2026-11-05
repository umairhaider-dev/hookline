"""Synthetic dataset and evaluation of the rules-only, AI-only and combined modes."""

from hookline.evaluation.dataset import Entry, load_dataset, write_dataset
from hookline.evaluation.generator import PROTECTED_DOMAINS, Sample, generate
from hookline.evaluation.metrics import Confusion, confusion
from hookline.evaluation.runner import EvaluationResult, run_evaluation
from hookline.evaluation.summary import render_markdown, summary_table

__all__ = [
    "PROTECTED_DOMAINS",
    "Confusion",
    "Entry",
    "EvaluationResult",
    "Sample",
    "confusion",
    "generate",
    "load_dataset",
    "render_markdown",
    "run_evaluation",
    "summary_table",
    "write_dataset",
]
