"""
Small filesystem helper: keep state files owned by their directory's owner.

The rotator has three writers of state under ``state/``:
  - ``ProtonClient._save()`` writes ``session.json``
  - ``HotLoopState.save()`` writes ``hotloop.json``
  - ``Library.save()`` writes ``library.json``

Two of the three services that call them run as root (swap-check,
health-check, api) and one runs as user (refresh). Without care, a
root write leaves the file owned by ``root:root``, and the next
user-run of refresh can't read ``state/session.json`` (chmod 0600),
crashing the refresh timer.

This module provides ``chown_to_parent_owner()`` which we call after
every state-file write. As root, it hands the file back to whoever
owns the parent directory. Non-root callers get a no-op.
"""

from __future__ import annotations

import os
from pathlib import Path


def chown_to_parent_owner(path: Path) -> None:
    """
    If running as root, chown ``path`` to match the owner of its parent
    directory. No-op for non-root callers or when the ownership already
    matches. Silently swallows chown errors (permissions edge cases on
    non-standard filesystems).
    """
    try:
        if os.geteuid() != 0:
            return
        parent_stat = path.parent.stat()
        parent_uid = parent_stat.st_uid
        parent_gid = parent_stat.st_gid
        # Root-owned parent → leaving root-owned children is correct.
        if parent_uid == 0 and parent_gid == 0:
            return
        st = path.stat()
        if st.st_uid == parent_uid and st.st_gid == parent_gid:
            return
        os.chown(path, parent_uid, parent_gid)
    except (FileNotFoundError, PermissionError, OSError):
        # Don't let ownership hygiene break a legitimate write.
        pass
