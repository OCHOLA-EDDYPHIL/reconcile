"""Deterministic evidence normalization, classification, and reporting."""

from reconcile.evidence.admission import (
    EvidenceAttempt,
    EvidencePipeline,
    ProbeRun,
)
from reconcile.evidence.classification import CoreEvaluation, evaluate_evidence
from reconcile.evidence.engine import EvidenceEngine
from reconcile.evidence.reporting import build_report
from reconcile.evidence.rules import (
    DuplicateTargetRule,
    RuleInput,
    RuleObservation,
    RuleRejected,
    RuleRequest,
    RuleVerdict,
    TargetNormalizer,
    TargetRuleDescriptor,
    TargetRuleRegistration,
    TargetRuleRegistry,
    TargetRuleRegistryFrozen,
)

__all__ = [
    "CoreEvaluation",
    "DuplicateTargetRule",
    "EvidenceAttempt",
    "EvidenceEngine",
    "EvidencePipeline",
    "ProbeRun",
    "RuleInput",
    "RuleObservation",
    "RuleRejected",
    "RuleRequest",
    "RuleVerdict",
    "TargetNormalizer",
    "TargetRuleDescriptor",
    "TargetRuleRegistration",
    "TargetRuleRegistry",
    "TargetRuleRegistryFrozen",
    "build_report",
    "evaluate_evidence",
]
