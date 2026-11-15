"""CRUX-compatible package version comparator (vercmp)."""

from __future__ import annotations

import functools
import re

_PRE_RELEASE_TAGS = {"alpha": -4, "beta": -3, "pre": -2, "rc": -1}
_TOKEN_RE = re.compile(r"([0-9]+|[a-zA-Z]+)")


def split_version_release(ver_str: str) -> tuple[str, int | None]:
    """Split '1.21.0-1' into ('1.21.0', 1), or '1.21.0' into ('1.21.0', None)."""
    s = ver_str.strip()
    if "-" in s:
        base, rel = s.rsplit("-", 1)
        if base and rel.isdigit():
            return base, int(rel)
    return s, None


def _tokenize_version(ver: str) -> list[int | str]:
    tokens: list[int | str] = []
    for m in _TOKEN_RE.finditer(ver):
        tok = m.group(1)
        if tok.isdigit():
            tokens.append(int(tok))
        else:
            tokens.append(tok.lower())
    return tokens


def _token_weight(tok: int | str) -> tuple[int, int | str]:
    if isinstance(tok, int):
        return (2, tok)
    if tok in _PRE_RELEASE_TAGS:
        return (0, _PRE_RELEASE_TAGS[tok])
    return (1, tok)


def vercmp(v1: str, v2: str) -> int:
    """Compare two CRUX version (or version-release) strings.

    Returns:
      -1 if v1 < v2
       0 if v1 == v2
       1 if v1 > v2
    """
    b1, r1 = split_version_release(v1)
    b2, r2 = split_version_release(v2)

    t1 = _tokenize_version(b1)
    t2 = _tokenize_version(b2)

    n = min(len(t1), len(t2))
    for i in range(n):
        w1 = _token_weight(t1[i])
        w2 = _token_weight(t2[i])
        if w1 != w2:
            return -1 if w1 < w2 else 1

    if len(t1) != len(t2):
        if len(t1) > len(t2):
            extra = t1[n]
            # If extra token is a pre-release tag (e.g. 1.0rc1 vs 1.0), shorter is newer
            if isinstance(extra, str) and extra in _PRE_RELEASE_TAGS:
                return -1
            return 1
        else:
            extra = t2[n]
            if isinstance(extra, str) and extra in _PRE_RELEASE_TAGS:
                return 1
            return -1

    # Base versions are equal; compare release numbers if both have one
    if r1 is not None and r2 is not None:
        if r1 != r2:
            return -1 if r1 < r2 else 1

    return 0


@functools.total_ordering
class Version:
    """Comparable wrapper around a CRUX version string."""

    def __init__(self, value: str) -> None:
        self.value = value.strip()

    def __repr__(self) -> str:
        return f"Version({self.value!r})"

    def __str__(self) -> str:
        return self.value

    def __eq__(self, other: object) -> bool:
        if isinstance(other, Version):
            return vercmp(self.value, other.value) == 0
        if isinstance(other, str):
            return vercmp(self.value, other) == 0
        return NotImplemented

    def __lt__(self, other: object) -> bool:
        if isinstance(other, Version):
            return vercmp(self.value, other.value) < 0
        if isinstance(other, str):
            return vercmp(self.value, other) < 0
        return NotImplemented
