"""Exceptions raised by proof verification. The API layer maps them to HTTP 400."""


class InvalidProof(Exception):
    """A zero-knowledge proof or signature failed verification."""

    code = "INVALID_PROOF"


class InvalidOpening(InvalidProof):
    """The revealed (value, randomness) do not open the stored commitment."""

    code = "INVALID_OPENING"


class CommitmentMismatch(InvalidProof):
    """The reveal refers to a different commitment than the one stored at bid time."""

    code = "COMMITMENT_MISMATCH"
