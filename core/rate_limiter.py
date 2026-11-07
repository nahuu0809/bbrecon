"""Rate limiter for safe bug bounty scanning."""
import time
import threading
from collections import defaultdict


class RateLimiter:
    """Token-bucket rate limiter per host with adaptive backoff."""

    def __init__(self, requests_per_second: float = 10.0, burst: int = 5):
        self._rps = requests_per_second
        self._burst = burst
        self._tokens: dict[str, float] = defaultdict(lambda: float(burst))
        self._last_refill: dict[str, float] = {}
        self._backoff: dict[str, float] = defaultdict(float)
        self._lock = threading.Lock()

    def wait(self, host: str = "default") -> None:
        """Block until a request token is available for the given host."""
        while True:
            with self._lock:
                now = time.monotonic()
                # Refill tokens
                last = self._last_refill.get(host, now)
                elapsed = now - last
                self._tokens[host] = min(
                    float(self._burst),
                    self._tokens[host] + elapsed * self._rps,
                )
                self._last_refill[host] = now

                # Apply backoff if active
                backoff = self._backoff[host]
                if backoff > 0:
                    self._backoff[host] = max(0, backoff - elapsed)
                    if self._backoff[host] > 0:
                        wait_time = min(self._backoff[host], 2.0)
                        # Release lock before sleeping
                        break_and_sleep = wait_time
                    else:
                        break_and_sleep = 0
                else:
                    break_and_sleep = 0

                if break_and_sleep:
                    pass  # will sleep outside lock
                elif self._tokens[host] >= 1.0:
                    self._tokens[host] -= 1.0
                    return
                else:
                    # Not enough tokens — calculate wait
                    deficit = 1.0 - self._tokens[host]
                    break_and_sleep = deficit / self._rps

            time.sleep(break_and_sleep)

    def backoff(self, host: str = "default", seconds: float = 5.0) -> None:
        """Trigger backoff for a host (e.g. on 429 or connection reset)."""
        with self._lock:
            self._backoff[host] = max(self._backoff[host], seconds)

    def notify_rate_limit(self, host: str = "default") -> None:
        """Call when a 429 Too Many Requests is received."""
        self.backoff(host, seconds=10.0)

    def notify_error(self, host: str = "default") -> None:
        """Call on connection errors to slow down."""
        self.backoff(host, seconds=3.0)

    @property
    def rps(self) -> float:
        return self._rps

    @rps.setter
    def rps(self, value: float) -> None:
        with self._lock:
            self._rps = max(0.1, value)
