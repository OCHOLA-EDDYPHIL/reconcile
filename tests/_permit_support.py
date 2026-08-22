"""Focused fixtures for single-use permit tests."""

from __future__ import annotations

from typing import Any

from reconcile.contracts import (
    CertifiedTransition,
    VerifiedCertificate,
    canonical_sha256,
)
from reconcile.controller.permits import (
    dispatch_arguments_sha256,
    dispatch_precondition_sha256,
)
from tests.contract._factories import make_recovery_examples


def make_permit_certificate() -> tuple[
    VerifiedCertificate,
    dict[str, Any],
    dict[str, Any],
]:
    chain, _hypothesis, certificate, _witness, _permit = make_recovery_examples()
    target_node = chain.nodes[1]
    arguments = dict(target_node.semantic_action.semantic_arguments)
    precondition = {"service_etag": "etag-7"}
    transition = CertifiedTransition.model_validate(
        certificate.transition.model_copy(  # type: ignore[union-attr]
            update={
                "arguments_sha256": dispatch_arguments_sha256(arguments),
                "target_sha256": canonical_sha256(target_node.semantic_action.target),
                "precondition_sha256": dispatch_precondition_sha256(precondition),
            }
        )
    )
    bound = VerifiedCertificate.model_validate(
        certificate.model_copy(update={"transition": transition})
    )
    return bound, arguments, precondition
