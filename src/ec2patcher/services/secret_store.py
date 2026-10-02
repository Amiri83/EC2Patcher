"""Secrets at rest: the NVD API key and per-server SSH passwords, encrypted with Fernet.

The Fernet key lives in its own file in the application config directory (mode 0600),
created on first use and never stored in the database or the repository. Without the
right key file the stored secrets cannot be read: that is always reported as a clear
:class:`SecretError` asking the user to enter the secret again, never silently ignored.

No message, ``repr`` or log line of this module ever contains a secret.
"""

import logging
import os
import stat
import threading
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken

from ec2patcher import config
from ec2patcher.database import Database

logger = logging.getLogger(__name__)

KEY_FILE_MODE = 0o600
NVD_KEY_SETTING = "nvd_api_key_encrypted"


class SecretError(Exception):
    """A stored secret cannot be encrypted or decrypted. The message is user-facing and never
    contains the secret."""


class SecretBox:
    """Fernet encryption with the key file at ``key_path`` (created on first encryption)."""

    def __init__(self, key_path: Path | None = None):
        self.key_path = Path(key_path) if key_path else config.get_secret_key_path()
        self._lock = threading.Lock()

    def __repr__(self) -> str:
        return f"SecretBox(key_path={str(self.key_path)!r})"

    def _reenter(self, problem: str) -> SecretError:
        return SecretError(
            f"The encryption key file {self.key_path} {problem}, so the stored secret cannot "
            "be decrypted. Enter the secret again (it is then encrypted with the current key)."
        )

    def _read_key(self) -> bytes:
        try:
            mode = stat.S_IMODE(self.key_path.stat().st_mode)
            if mode & 0o077:
                self.key_path.chmod(KEY_FILE_MODE)
                logger.warning("Restricted the permissions of %s to 0600", self.key_path)
            return self.key_path.read_bytes().strip()
        except FileNotFoundError:
            raise self._reenter("is missing") from None
        except OSError as exc:
            raise self._reenter(f"cannot be read ({exc.strerror or 'I/O error'})") from None

    def _fernet(self, create: bool) -> Fernet:
        with self._lock:
            if create and not self.key_path.exists():
                self._create_key()
            key = self._read_key()
        try:
            return Fernet(key)
        except ValueError:
            raise self._reenter("is not a valid key") from None

    def _create_key(self) -> None:
        self.key_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        try:
            fd = os.open(self.key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, KEY_FILE_MODE)
        except FileExistsError:
            return
        except OSError as exc:
            raise SecretError(
                f"Cannot create the encryption key file {self.key_path}: "
                f"{exc.strerror or 'I/O error'}."
            ) from None
        with os.fdopen(fd, "wb") as handle:
            handle.write(Fernet.generate_key() + b"\n")
        os.chmod(self.key_path, KEY_FILE_MODE)  # regardless of the umask
        logger.info("Created the encryption key file %s (mode 0600)", self.key_path)

    def encrypt(self, plaintext: str) -> str:
        return self._fernet(create=True).encrypt(plaintext.encode("utf-8")).decode("ascii")

    def decrypt(self, token: str) -> str:
        fernet = self._fernet(create=False)  # never replace a missing key: report it
        try:
            return fernet.decrypt(token.encode("ascii")).decode("utf-8")
        except (InvalidToken, UnicodeError):
            raise self._reenter("does not match the key used to encrypt it") from None


class SecretStore:
    """The encrypted secrets kept in the application database."""

    def __init__(self, db: Database, box: SecretBox | None = None):
        self.db = db
        self.box = box or SecretBox()

    def __repr__(self) -> str:
        return f"SecretStore(db={str(self.db.path)!r}, box={self.box!r})"

    # --- per-server SSH passwords ------------------------------------------------------

    def encrypt(self, plaintext: str) -> str:
        return self.box.encrypt(plaintext)

    def server_password(self, server_id: int) -> str | None:
        """The stored SSH password of a server, or None. Raises :class:`SecretError` when it
        cannot be decrypted."""
        token = self.db.get_server_password(server_id)
        return None if token is None else self.box.decrypt(token)

    def set_server_password(self, server_id: int, password: str) -> None:
        self.db.set_server_password(server_id, self.box.encrypt(password))

    def clear_server_password(self, server_id: int) -> None:
        self.db.set_server_password(server_id, None)

    # --- NVD API key -------------------------------------------------------------------

    def has_nvd_key(self) -> bool:
        return self.db.get_setting(NVD_KEY_SETTING) is not None

    def nvd_key(self) -> str | None:
        """The NVD API key saved in Settings, or None. Raises :class:`SecretError`."""
        token = self.db.get_setting(NVD_KEY_SETTING)
        return None if token is None else self.box.decrypt(token)

    def set_nvd_key(self, key: str) -> None:
        self.db.set_setting(NVD_KEY_SETTING, self.box.encrypt(key))

    def clear_nvd_key(self) -> None:
        self.db.delete_setting(NVD_KEY_SETTING)


def mask(secret: str) -> str:
    """Only the last 4 characters, e.g. ``••••cdef``."""
    return "•" * 8 + secret[-4:]
