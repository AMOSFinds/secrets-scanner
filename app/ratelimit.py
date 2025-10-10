import asyncio, time, os


RATE_LIMIT_PER_MIN = int(os.getenv("RATE_LIMIT_PER_MIN", "60"))
MAX_CONCURRENCY = int(os.getenv("MAX_CONCURRENCY", "5"))


class AsyncRateLimiter:
    def __init__(self, per_min: int = RATE_LIMIT_PER_MIN):
        self.per_min = max(1, per_min)
        self.min_interval = 60.0 / self.per_min
        self._lock = asyncio.Lock()
        self._last = 0.0


    async def wait(self):
        async with self._lock:
            now = time.perf_counter()
            delta = now - self._last
            wait_for = self.min_interval - delta
            if wait_for > 0:
                await asyncio.sleep(wait_for)
            self._last = time.perf_counter()


limiter = AsyncRateLimiter(RATE_LIMIT_PER_MIN)
sema = asyncio.Semaphore(MAX_CONCURRENCY)