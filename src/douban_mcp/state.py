"""Local owner-only state; atomic replacement and cross-process transaction locks."""

import fcntl
import json
import os
import secrets
import tempfile
from contextlib import contextmanager
from pathlib import Path


class StateError(Exception):
    pass


class StateStore:
    def __init__(self, directory: Path):
        self.directory = directory

    def _prepare(self):
        if self.directory.is_symlink():
            raise StateError("State directory must be a real directory")
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.directory.chmod(0o700)

    @contextmanager
    def locked(self):
        self._prepare()
        fd = os.open(self.directory / ".lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            # Fail promptly when another backend is changing credentials.
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise StateError("Credentials are busy in another process; try again") from None
            yield
        finally:
            os.close(fd)

    def read(self, name: str) -> dict:
        path = self.directory / name
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        except FileNotFoundError:
            return {}
        try:
            with os.fdopen(fd) as stream:
                value = json.load(stream)
            if not isinstance(value, dict):
                raise TypeError
            return value
        except (ValueError, TypeError):
            raise StateError(f"Invalid local state: {name}; restore or remove this file") from None

    def write(self, name: str, value: dict):
        self._prepare()
        fd, tmp = tempfile.mkstemp(prefix=".tmp-", dir=self.directory)
        try:
            with os.fdopen(fd, "w") as stream:
                json.dump(value, stream, ensure_ascii=False)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(tmp, self.directory / name)
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)

    def device(self, override: str | None) -> str:
        with self.locked():
            value = override or self.read("device.json").get("device_id")
            if not value:
                value = secrets.token_hex(20)
            if (
                not isinstance(value, str)
                or len(value) not in (20, 40)
                or any(c not in "0123456789abcdef" for c in value)
            ):
                raise StateError("Device ID must contain 20 or 40 lowercase hexadecimal characters")
            self.write("device.json", {"device_id": value})
            return value

    def clear_tokens(self):
        (self.directory / "credentials.json").unlink(missing_ok=True)
