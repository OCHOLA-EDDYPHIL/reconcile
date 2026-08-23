"""Firestore release-record and trusted dispatch-receipt recovery probes."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Literal, Protocol

from reconcile.contracts import (
    OBSERVATION_CAPABILITY_VERSION,
    EffectAssertion,
    EffectAssertionState,
    EvidenceReason,
    ObservationCapability,
    OperationStatus,
    RecoveryDispatchReceipt,
    RecoveryReceiptOutcome,
    TargetBinding,
    TargetConstraint,
    canonical_json_bytes,
)
from reconcile.contracts.base import Identifier, Sha256Digest, StrictModel
from reconcile.controller import (
    BoundProbe,
    CapabilityRegistration,
    CapabilitySemantics,
    CapabilityUnavailable,
    ProbeObservation,
)
from reconcile.evidence import (
    RuleInput,
    RuleObservation,
    RuleRejected,
    RuleVerdict,
    TargetRuleDescriptor,
    TargetRuleRegistration,
)
from reconcile.evidence.recovery_rules import (
    DISPATCH_RECEIPT_ADAPTER_VERSION,
    DISPATCH_RECEIPT_OBSERVATION_VERSION,
    DISPATCH_RECEIPT_SOURCE,
    FIRESTORE_DOCUMENT_OBSERVATION_VERSION,
    FIRESTORE_DOCUMENT_TARGET_KIND,
    FIRESTORE_PROVIDER_ADAPTER_VERSION,
    FIRESTORE_PROVIDER_SOURCE,
    FIRESTORE_RECORD_EFFECT_SCOPE,
    RECOVERY_CAPABILITY_VERSION,
)
from reconcile.hosted.firestore_release import (
    FirestoreReleaseError,
    FirestoreReleaseSnapshot,
    GoogleFirestoreReleaseTarget,
)

FIRESTORE_RELEASE_CAPABILITY = "firestore-release-record-get"
DISPATCH_RECEIPT_CAPABILITY = "reconcile-dispatch-receipt-get"
FIRESTORE_RELEASE_AUTHORITY_POLICY_VERSION = "recovery-authority-v1"
FIRESTORE_RELEASE_CLASSIFICATION_POLICY_VERSION = "recovery-classification-v1"

_TARGET_SCOPE = frozenset({"project", "database"})
_TARGET_RESOURCE = frozenset({"document"})
_TIMEOUT_MS = 5_000


class _ObservationPayload(StrictModel):
    observation: dict[str, object] | None


class _DocumentObservation(StrictModel):
    observation_schema: Literal[FIRESTORE_DOCUMENT_OBSERVATION_VERSION]
    release_id: Identifier
    cloud_run_revision: Identifier
    payload_sha256: Sha256Digest
    semantic_action_sha256: Sha256Digest
    exists: Literal["true", "false"]


class _ReceiptObservation(StrictModel):
    observation_schema: Literal[DISPATCH_RECEIPT_OBSERVATION_VERSION]
    release_id: Identifier
    semantic_action_sha256: Sha256Digest
    receipt_id: Identifier
    provider_contact: Literal["false"]
    outcome: Literal[
        "SUPPRESSED_BEFORE_DISPATCH",
        "AUTHORITATIVE_REJECTION_BEFORE_PROVIDER_CONTACT",
    ]


@dataclass(frozen=True, slots=True)
class FirestoreReleaseProbeBinding:
    run_id: str
    node_id: str
    attempt: int
    release_id: str
    cloud_run_revision: str
    payload_sha256: str
    semantic_action_sha256: str

    def __post_init__(self) -> None:
        try:
            _ReceiptObservation(
                observation_schema=DISPATCH_RECEIPT_OBSERVATION_VERSION,
                release_id=self.release_id,
                semantic_action_sha256=self.semantic_action_sha256,
                receipt_id="binding-validation",
                provider_contact="false",
                outcome="SUPPRESSED_BEFORE_DISPATCH",
            )
        except Exception as error:
            raise ValueError("Firestore release probe binding is invalid") from error
        if not self.run_id or not self.node_id or not 1 <= self.attempt <= 2:
            raise ValueError("Firestore release probe binding is incomplete")
        try:
            _DocumentObservation(
                observation_schema=FIRESTORE_DOCUMENT_OBSERVATION_VERSION,
                release_id=self.release_id,
                cloud_run_revision=self.cloud_run_revision,
                payload_sha256=self.payload_sha256,
                semantic_action_sha256=self.semantic_action_sha256,
                exists="false",
            )
        except Exception as error:
            raise ValueError("Firestore release probe binding is invalid") from error


class DispatchReceiptReader(Protocol):
    async def latest_dispatch_receipt(
        self,
        *,
        run_id: str,
        node_id: str,
        attempt: int,
        semantic_action_sha256: str,
    ) -> RecoveryDispatchReceipt | None: ...


def build_firestore_release_target(
    *, project: str, database: str, document: str
) -> TargetBinding:
    if any(
        type(value) is not str or not value or len(value) > 512
        for value in (project, database, document)
    ):
        raise ValueError("Firestore release target is invalid")
    if any(character.isspace() for character in document) or (
        document.startswith("/") or document.endswith("/") or "//" in document
    ):
        raise ValueError("Firestore release document path is invalid")
    return TargetBinding(
        target_kind=FIRESTORE_DOCUMENT_TARGET_KIND,
        scope={"project": project, "database": database},
        resource={"document": document},
    )


def _target_coordinates(target: TargetBinding) -> tuple[str, str, str]:
    if (
        target.target_kind != FIRESTORE_DOCUMENT_TARGET_KIND
        or set(target.scope) != _TARGET_SCOPE
        or set(target.resource) != _TARGET_RESOURCE
    ):
        raise ValueError("Firestore release target does not match the sealed profile")
    project = target.scope["project"]
    database = target.scope["database"]
    document = target.resource["document"]
    if any(
        type(value) is not str or not value for value in (project, database, document)
    ):
        raise ValueError("Firestore release target coordinates are invalid")
    return project, database, document


def build_firestore_release_capability(
    *, capability_name: str, target: TargetBinding
) -> ObservationCapability:
    if capability_name not in {
        FIRESTORE_RELEASE_CAPABILITY,
        DISPATCH_RECEIPT_CAPABILITY,
    }:
        raise ValueError("Firestore release capability is unsupported")
    _target_coordinates(target)
    return ObservationCapability(
        schema_version=OBSERVATION_CAPABILITY_VERSION,
        name=capability_name,
        version=RECOVERY_CAPABILITY_VERSION,
        read_only=True,
        argument_schema={
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "type": "object",
            "properties": {},
            "required": [],
            "additionalProperties": False,
        },
        allowed_targets=(
            TargetConstraint(target_kind=target.target_kind, scope=dict(target.scope)),
        ),
        timeout_ms=_TIMEOUT_MS,
        result_byte_ceiling=8_192,
        cost_units=1,
    )


@dataclass(frozen=True, slots=True)
class _ReadHandler:
    target: GoogleFirestoreReleaseTarget = field(repr=False, compare=False)
    receipts: DispatchReceiptReader = field(repr=False, compare=False)
    binding: FirestoreReleaseProbeBinding
    capability_name: str
    target_bytes: bytes = field(repr=False)
    clock: object = field(repr=False, compare=False)

    async def __call__(self, probe: BoundProbe) -> ProbeObservation:
        if (
            probe.capability_name != self.capability_name
            or probe.capability_version != RECOVERY_CAPABILITY_VERSION
            or probe.arguments != {}
            or canonical_json_bytes(probe.target) != self.target_bytes
        ):
            raise CapabilityUnavailable
        try:
            if self.capability_name == FIRESTORE_RELEASE_CAPABILITY:
                snapshot = await self.target.read(self.binding.release_id)
                observed_at = self.clock() if snapshot is None else snapshot.observed_at
                observation = _document_payload(snapshot, self.binding)
            else:
                receipt = await self.receipts.latest_dispatch_receipt(
                    run_id=self.binding.run_id,
                    node_id=self.binding.node_id,
                    attempt=self.binding.attempt,
                    semantic_action_sha256=self.binding.semantic_action_sha256,
                )
                observed_at = self.clock() if receipt is None else receipt.recorded_at
                observation = _receipt_payload(receipt, self.binding)
            if not isinstance(observed_at, datetime) or observed_at.tzinfo is None:
                raise ValueError
        except asyncio.CancelledError:
            raise
        except (FirestoreReleaseError, TypeError, ValueError):
            raise CapabilityUnavailable from None
        return ProbeObservation(
            observed_at=observed_at.astimezone(UTC),
            payload={"observation": observation},
        )


def _document_payload(
    snapshot: FirestoreReleaseSnapshot | None,
    binding: FirestoreReleaseProbeBinding,
) -> dict[str, object]:
    if snapshot is None:
        return {
            "observation_schema": FIRESTORE_DOCUMENT_OBSERVATION_VERSION,
            "release_id": binding.release_id,
            "cloud_run_revision": binding.cloud_run_revision,
            "payload_sha256": binding.payload_sha256,
            "semantic_action_sha256": binding.semantic_action_sha256,
            "exists": "false",
        }
    record = snapshot.record
    return {
        "observation_schema": FIRESTORE_DOCUMENT_OBSERVATION_VERSION,
        "release_id": record.release_id,
        "cloud_run_revision": record.cloud_run_revision,
        "payload_sha256": record.payload_sha256,
        "semantic_action_sha256": record.semantic_action_sha256,
        "exists": "true",
    }


def _receipt_payload(
    receipt: RecoveryDispatchReceipt | None,
    binding: FirestoreReleaseProbeBinding,
) -> dict[str, object] | None:
    if receipt is None:
        return None
    if (
        receipt.run_id != binding.run_id
        or receipt.node_id != binding.node_id
        or receipt.release_id != binding.release_id
        or receipt.semantic_action_sha256 != binding.semantic_action_sha256
        or receipt.provider_contact
        or receipt.outcome is RecoveryReceiptOutcome.PROVIDER_CONTACTED
    ):
        raise ValueError("dispatch receipt is not authoritative non-execution")
    outcome = {
        RecoveryReceiptOutcome.SUPPRESSED_BEFORE_DISPATCH: (
            "SUPPRESSED_BEFORE_DISPATCH"
        ),
        RecoveryReceiptOutcome.REJECTED_BEFORE_PROVIDER_CONTACT: (
            "AUTHORITATIVE_REJECTION_BEFORE_PROVIDER_CONTACT"
        ),
    }[receipt.outcome]
    return {
        "observation_schema": DISPATCH_RECEIPT_OBSERVATION_VERSION,
        "release_id": receipt.release_id,
        "semantic_action_sha256": receipt.semantic_action_sha256,
        "receipt_id": receipt.receipt_id,
        "provider_contact": "false",
        "outcome": outcome,
    }


def build_firestore_release_capability_registration(
    *,
    target: GoogleFirestoreReleaseTarget,
    receipts: DispatchReceiptReader,
    binding: FirestoreReleaseProbeBinding,
    capability_name: str,
    action_target: TargetBinding,
    clock: object | None = None,
) -> CapabilityRegistration:
    if type(target) is not GoogleFirestoreReleaseTarget:
        raise TypeError("Firestore release capability requires the sealed target")
    if not callable(getattr(receipts, "latest_dispatch_receipt", None)):
        raise TypeError("Firestore release capability requires a receipt reader")
    project, database, _document = _target_coordinates(action_target)
    if (target.project_id, target.database_id) != (project, database):
        raise ValueError("Firestore release reader and action target differ")
    if clock is not None and not callable(clock):
        raise TypeError("Firestore release capability clock must be callable")
    return CapabilityRegistration(
        capability=build_firestore_release_capability(
            capability_name=capability_name,
            target=action_target,
        ),
        semantics=CapabilitySemantics.READ_ONLY,
        enabled=True,
        argument_byte_ceiling=2,
        max_invocations=4,
        handler=_ReadHandler(
            target=target,
            receipts=receipts,
            binding=binding,
            capability_name=capability_name,
            target_bytes=canonical_json_bytes(action_target),
            clock=clock or (lambda: datetime.now(UTC)),
        ),
    )


@dataclass(frozen=True, slots=True)
class FirestoreReleaseObservationNormalizer:
    capability_name: str
    binding: FirestoreReleaseProbeBinding

    def __post_init__(self) -> None:
        if self.capability_name not in {
            FIRESTORE_RELEASE_CAPABILITY,
            DISPATCH_RECEIPT_CAPABILITY,
        }:
            raise ValueError("Firestore release normalizer is unsupported")

    def __call__(self, rule_input: RuleInput) -> RuleObservation:
        if type(rule_input) is not RuleInput:
            raise RuleRejected(EvidenceReason.MALFORMED_OBSERVATION)
        request = rule_input.request
        if (
            request.capability_name != self.capability_name
            or request.capability_version != RECOVERY_CAPABILITY_VERSION
            or request.arguments != {}
        ):
            raise RuleRejected(EvidenceReason.MALFORMED_OBSERVATION)
        try:
            raw = ProbeObservation.model_validate_json(rule_input.observation)
            wrapper = _ObservationPayload.model_validate(raw.payload)
            effect = next(
                item
                for item in rule_input.envelope.expected_effects
                if item.effect_id in request.relevant_effect_ids
            )
            if effect.commit_scope != FIRESTORE_RECORD_EFFECT_SCOPE:
                raise ValueError
            expected = {
                "release_id": self.binding.release_id,
                "cloud_run_revision": self.binding.cloud_run_revision,
                "payload_sha256": self.binding.payload_sha256,
            }
            if effect.predicate != expected:
                raise ValueError
            skew = timedelta(
                seconds=rule_input.envelope.context.freshness.clock_skew_seconds
            )
            horizon = (
                timedelta(seconds=rule_input.envelope.context.freshness.max_age_seconds)
                + skew
            )
            if (
                raw.observed_at > rule_input.retrieved_at + skew
                or rule_input.envelope.invoked_at - raw.observed_at > skew
                or rule_input.retrieved_at - raw.observed_at > horizon
            ):
                raise ValueError
            project, database, document = _target_coordinates(
                rule_input.envelope.target
            )
            if self.capability_name == FIRESTORE_RELEASE_CAPABILITY:
                typed = _DocumentObservation.model_validate(wrapper.observation)
                if (
                    typed.release_id != self.binding.release_id
                    or typed.cloud_run_revision != self.binding.cloud_run_revision
                    or typed.payload_sha256 != self.binding.payload_sha256
                    or typed.semantic_action_sha256
                    != self.binding.semantic_action_sha256
                ):
                    raise ValueError
                state = (
                    EffectAssertionState.ESTABLISHED
                    if typed.exists == "true"
                    else EffectAssertionState.UNVERIFIED
                )
                return RuleObservation(
                    target=rule_input.envelope.target,
                    source_record=(
                        f"projects/{project}/databases/{database}/documents/{document}"
                    ),
                    observed_at=raw.observed_at,
                    operation_id=(
                        rule_input.envelope.operation_id
                        if typed.exists == "true"
                        else None
                    ),
                    correlation=typed.model_dump(mode="json"),
                    effect_assertions=(
                        EffectAssertion(effect_id=effect.effect_id, state=state),
                    ),
                    verdict=(
                        RuleVerdict.AUTHORITATIVE_EFFECTS
                        if typed.exists == "true"
                        else RuleVerdict.ABSENCE_ONLY
                    ),
                )
            typed_receipt = _ReceiptObservation.model_validate(wrapper.observation)
            if (
                typed_receipt.release_id != self.binding.release_id
                or typed_receipt.semantic_action_sha256
                != self.binding.semantic_action_sha256
            ):
                raise ValueError
            return RuleObservation(
                target=rule_input.envelope.target,
                source_record=f"dispatch-receipts/{typed_receipt.receipt_id}",
                observed_at=raw.observed_at,
                operation_id=rule_input.envelope.operation_id,
                correlation=typed_receipt.model_dump(mode="json"),
                effect_assertions=(
                    EffectAssertion(
                        effect_id=effect.effect_id,
                        state=EffectAssertionState.NOT_ESTABLISHED,
                    ),
                ),
                operation_status=OperationStatus.TERMINAL_NOT_COMMITTED,
                verdict=RuleVerdict.AUTHORITATIVE_NON_EXECUTION,
            )
        except (StopIteration, TypeError, ValueError) as error:
            raise RuleRejected(EvidenceReason.MALFORMED_OBSERVATION) from error


def build_firestore_release_rule_registration(
    *,
    capability_name: str,
    binding: FirestoreReleaseProbeBinding,
) -> TargetRuleRegistration:
    source, adapter = {
        FIRESTORE_RELEASE_CAPABILITY: (
            FIRESTORE_PROVIDER_SOURCE,
            FIRESTORE_PROVIDER_ADAPTER_VERSION,
        ),
        DISPATCH_RECEIPT_CAPABILITY: (
            DISPATCH_RECEIPT_SOURCE,
            DISPATCH_RECEIPT_ADAPTER_VERSION,
        ),
    }[capability_name]
    return TargetRuleRegistration(
        descriptor=TargetRuleDescriptor(
            target_kind=FIRESTORE_DOCUMENT_TARGET_KIND,
            capability_name=capability_name,
            capability_version=RECOVERY_CAPABILITY_VERSION,
            authority_policy_version=FIRESTORE_RELEASE_AUTHORITY_POLICY_VERSION,
            classification_policy_version=(
                FIRESTORE_RELEASE_CLASSIFICATION_POLICY_VERSION
            ),
            source=source,
            adapter_version=adapter,
        ),
        normalizer=FirestoreReleaseObservationNormalizer(
            capability_name=capability_name,
            binding=binding,
        ),
    )


__all__ = [
    "DISPATCH_RECEIPT_CAPABILITY",
    "FIRESTORE_RELEASE_AUTHORITY_POLICY_VERSION",
    "FIRESTORE_RELEASE_CAPABILITY",
    "FIRESTORE_RELEASE_CLASSIFICATION_POLICY_VERSION",
    "DispatchReceiptReader",
    "FirestoreReleaseObservationNormalizer",
    "FirestoreReleaseProbeBinding",
    "build_firestore_release_capability",
    "build_firestore_release_capability_registration",
    "build_firestore_release_rule_registration",
    "build_firestore_release_target",
]
