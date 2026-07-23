"""Resolve database secret references from an immutable mounted secret root."""

from __future__ import annotations

import os
from pathlib import Path, PurePosixPath
import re


_REFERENCE = re.compile(r"^mounted:([A-Za-z0-9][A-Za-z0-9._/-]{0,503})$")


class SecretReferenceError(ValueError):
    pass


class MountedSecretProvider:
    def __init__(self, root: Path, *, maximum_bytes: int = 65536) -> None:
        self._root = root.resolve(strict=True)
        if not self._root.is_dir():
            raise SecretReferenceError("secret root is not a directory")
        if not 1 <= maximum_bytes <= 1048576:
            raise SecretReferenceError("secret size limit is invalid")
        self._maximum_bytes = maximum_bytes

    def read(self, reference: str) -> bytes:
        match = _REFERENCE.fullmatch(reference)
        if match is None:
            raise SecretReferenceError("secret reference must use the mounted: scheme")
        relative = PurePosixPath(match.group(1))
        if relative.is_absolute() or any(part in {"", ".", ".."} for part in relative.parts):
            raise SecretReferenceError("secret reference escapes its namespace")
        candidate = self._root.joinpath(*relative.parts)
        try:
            resolved = candidate.resolve(strict=True)
            resolved.relative_to(self._root)
        except (OSError, ValueError) as exc:
            raise SecretReferenceError("secret reference is unavailable") from exc
        if not resolved.is_file():
            raise SecretReferenceError("secret reference is not a regular file")
        try:
            descriptor = os.open(resolved, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            try:
                value = os.read(descriptor, self._maximum_bytes + 1)
            finally:
                os.close(descriptor)
        except OSError as exc:
            raise SecretReferenceError("secret reference is unreadable") from exc
        value = value.rstrip(b"\r\n")
        if not value or len(value) > self._maximum_bytes:
            raise SecretReferenceError("secret value is empty or too large")
        return value
