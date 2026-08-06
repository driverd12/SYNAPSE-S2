"""Shared bounded policy for authoritative-core replacement capture debt."""

from __future__ import annotations


REPLACEMENT_CAPTURE_MAX_BATCHES = 32
REPLACEMENT_CAPTURE_MAX_PENDING_FILES = 1_000


def replacement_capture_pending_limit(
    *,
    batch_size: int,
    batch_count: int,
) -> int:
    """Return the finite signed queue limit shared by producer and consumer."""

    if type(batch_size) is not int or batch_size <= 0:
        raise ValueError("replacement capture batch size is invalid")
    if (
        type(batch_count) is not int
        or batch_count <= 0
        or batch_count > REPLACEMENT_CAPTURE_MAX_BATCHES
    ):
        raise ValueError(
            "replacement capture batch count must be between 1 and "
            f"{REPLACEMENT_CAPTURE_MAX_BATCHES}"
        )
    return min(
        batch_size * batch_count,
        REPLACEMENT_CAPTURE_MAX_PENDING_FILES,
    )
