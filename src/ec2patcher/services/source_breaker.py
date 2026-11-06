"""Circuit breakers per (source, endpoint), kept in memory; there is no global breaker.

After ``threshold`` consecutive failures a breaker opens. Once its backoff has passed it goes
half-open and lets one trial through: a success closes it, a failure opens it again with the
backoff doubled (up to ``max_backoff``). A blocked ubuntu.com therefore never disables
security.ubuntu.com, NVD, KEV or EPSS. Every transition is logged.
"""

import logging
import threading
import time
from collections.abc import Callable

logger = logging.getLogger(__name__)

CLOSED, OPEN, HALF_OPEN = "closed", "open", "half-open"
DEFAULT_THRESHOLD = 3
DEFAULT_BACKOFF_SECONDS = 60.0
MAX_BACKOFF_SECONDS = 900.0


class SourceBreaker:
    def __init__(
        self,
        source: str,
        endpoint: str,
        threshold: int = DEFAULT_THRESHOLD,
        backoff: float = DEFAULT_BACKOFF_SECONDS,
        max_backoff: float = MAX_BACKOFF_SECONDS,
        monotonic: Callable[[], float] = time.monotonic,
    ):
        self.source, self.endpoint = source, endpoint
        self.threshold = max(1, threshold)
        self.base_backoff, self.max_backoff = backoff, max_backoff
        self.monotonic = monotonic
        self._lock = threading.Lock()
        self.state = CLOSED
        self.failures = 0
        self.reason: str | None = None
        self.backoff = backoff
        self._retry_at = 0.0

    def _move(self, target: str) -> None:
        # Caller holds the lock.
        if target == self.state:
            return
        logger.warning(
            "source_breaker source=%s endpoint=%s transition=%s->%s failures=%d backoff_s=%g "
            "reason=%s",
            self.source, self.endpoint, self.state, target, self.failures, self.backoff,
            self.reason,
        )  # fmt: skip
        self.state = target

    def allow(self) -> bool:
        """May a request go out now? A half-open breaker lets one trial through per backoff."""
        with self._lock:
            if self.state == CLOSED:
                return True
            now = self.monotonic()
            if now < self._retry_at:
                return False
            self._retry_at = now + self.backoff
            self._move(HALF_OPEN)
            return True

    def success(self) -> None:
        with self._lock:
            self.failures, self.reason, self.backoff = 0, None, self.base_backoff
            self._move(CLOSED)

    def failure(self, reason: str) -> None:
        with self._lock:
            self.failures += 1
            self.reason = reason
            if self.state == HALF_OPEN:
                self.backoff = min(self.backoff * 2, self.max_backoff)
            elif self.state == CLOSED and self.failures < self.threshold:
                return
            self._retry_at = self.monotonic() + self.backoff
            self._move(OPEN)

    def reset(self) -> None:
        self.success()


class BreakerBoard:
    """The breakers of one process, one per (source, endpoint), created on first use."""

    def __init__(
        self,
        threshold: int = DEFAULT_THRESHOLD,
        backoff: float = DEFAULT_BACKOFF_SECONDS,
        monotonic: Callable[[], float] = time.monotonic,
    ):
        self.threshold, self.backoff, self.monotonic = threshold, backoff, monotonic
        self._breakers: dict[tuple[str, str], SourceBreaker] = {}
        self._lock = threading.Lock()

    def get(self, source: str, endpoint: str) -> SourceBreaker:
        with self._lock:
            key = (source, endpoint)
            if key not in self._breakers:
                self._breakers[key] = SourceBreaker(
                    source, endpoint, self.threshold, self.backoff, monotonic=self.monotonic
                )
            return self._breakers[key]

    def reset(self) -> None:
        with self._lock:
            breakers = list(self._breakers.values())
        for breaker in breakers:
            breaker.reset()
