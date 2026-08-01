"""Segment-aware namespace matching (Dacar spec §3.3).

Namespaces within an Object string are delimited by ``:``. The suffix
wildcard ``*`` matches all subsequent segments and MUST be the terminal
segment of a tuple's Object string.
"""

from __future__ import annotations

from typing import List

DELIMITER = ":"
WILDCARD = "*"


def split(object_id: str) -> List[str]:
    """Split an object string into its segments.

    The empty object collapses to a single empty segment, which keeps the
    wildcard machinery well-defined for the root namespace.
    """
    return object_id.split(DELIMITER)


def match(tuple_object: str, requested_object: str) -> bool:
    """Return True if ``requested_object`` is covered by ``tuple_object``.

    Implements the §3.3 matching algorithm:

      1. Split both strings by ``:``.
      2. Compare segments sequentially.
      3. If the tuple object segment is ``*``, match immediately succeeds.
      4. If any segments differ before a ``*`` is reached, the match fails.
    """
    t = split(tuple_object)
    r = split(requested_object)
    for i, seg in enumerate(t):
        if seg == WILDCARD:
            return True
        if i >= len(r) or seg != r[i]:
            return False
    # No wildcard reached; the request must be exactly as long as the tuple.
    return len(t) == len(r)


def permutations(object_id: str) -> List[str]:
    """Generate the exact and suffix-wildcard patterns that cover ``object_id``.

    For ``a:b:c`` this yields ``["a:b:c", "a:b:*", "a:*", "*"]`` (order is not
    significant). Each generated pattern is a legal terminal-wildcard object.
    """
    segments = split(object_id)
    n = len(segments)
    patterns: List[str] = []
    # Shorter prefixes, each terminated by a wildcard.
    for i in range(n - 1, -1, -1):
        patterns.append(DELIMITER.join(segments[:i] + [WILDCARD]))
    # The exact object itself.
    patterns.append(object_id)
    return patterns
