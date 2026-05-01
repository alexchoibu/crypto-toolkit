"""
baseline — rule-based cryptographic artifact identifier.

Public API
----------
    from baseline.artifact_identifier import ArtifactIdentifier, IdentificationResult

    identifier = ArtifactIdentifier()
    result = identifier.identify("d41d8cd98f00b204e9800998ecf8427e")
    # IdentificationResult(artifact_type='hash', algorithm='MD5', confidence=0.75, ...)

    results = identifier.identify_batch(["SGVsbG8=", "Pdau zayezaz..."])
"""

from .artifact_identifier import ArtifactIdentifier, IdentificationResult

__all__ = ["ArtifactIdentifier", "IdentificationResult"]
