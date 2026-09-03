"""Robust POSIX-style path confinement.

Paths declared in policy roots are always treated as an abstract POSIX
namespace (forward-slash separated), independent of the host OS the bouncer
happens to run on -- the paths belong to the *upstream MCP server*, not
necessarily to the bouncer's own filesystem.

Containment is decided by component-wise comparison (never raw string
``startswith``), which is what correctly rejects the separator-less prefix
case: root ``/srv/app`` must NOT contain ``/srv/appdata``.

Handles, in order:
  - unicode separator look-alikes (fullwidth solidus etc.) via NFKC
  - backslash treated as an additional separator
  - lexical ``.`` / ``..`` resolution (cannot climb above an absolute root)
  - absolute vs relative paths
  - real filesystem symlink resolution, when the resolved path exists on
    the local disk (defense in depth; falls back to lexical-only otherwise)
"""

from __future__ import annotations

import os
import posixpath
import unicodedata


def normalize_separators(raw: str) -> str:
    """NFKC-normalize (folds fullwidth/unicode slash look-alikes to ASCII),
    then also treat backslash as a path separator."""
    normalized = unicodedata.normalize("NFKC", raw)
    return normalized.replace("\\", "/")


def lexical_resolve(path: str) -> str:
    """Resolve ``.`` and ``..`` purely lexically against an absolute POSIX
    root, without touching the filesystem. Non-absolute input is treated as
    rooted at ``/`` (policy roots are always absolute; a relative arg is
    conservatively anchored at the root rather than left ambiguous)."""
    normalized = normalize_separators(path)
    if not posixpath.isabs(normalized):
        normalized = "/" + normalized
    parts = normalized.split("/")
    stack: list[str] = []
    for part in parts:
        if part in ("", "."):
            continue
        if part == "..":
            if stack:
                stack.pop()
            continue
        stack.append(part)
    return "/" + "/".join(stack)


def _components(posix_path: str) -> list[str]:
    return [p for p in posix_path.split("/") if p]


def _to_posix(native_path: str) -> str:
    return native_path.replace(os.sep, "/").replace("\\", "/")


def resolve_path(raw: str) -> str:
    """Best-effort resolution: lexical POSIX resolution, then real-filesystem
    realpath (to catch symlink escapes) if the lexical result exists on
    the local disk. Returns a POSIX-style absolute string."""
    lexical = lexical_resolve(raw)
    try:
        if os.path.lexists(lexical):
            real = os.path.realpath(lexical)
            return _to_posix(real)
    except OSError:
        pass
    return lexical


def is_under_root(raw: str, root: str) -> tuple[bool, str]:
    """Returns (is_contained, resolved_path). Containment is a component-wise
    prefix match -- never a raw string prefix -- so a root of ``/srv/app``
    does not accidentally admit ``/srv/appdata``."""
    resolved = resolve_path(raw)
    root_resolved = lexical_resolve(root)
    resolved_parts = _components(resolved)
    root_parts = _components(root_resolved)
    if len(resolved_parts) < len(root_parts):
        return False, resolved
    return resolved_parts[: len(root_parts)] == root_parts, resolved
