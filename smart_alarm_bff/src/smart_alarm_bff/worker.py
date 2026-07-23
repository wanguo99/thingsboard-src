"""Fenced PostgreSQL outbox worker kernel."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
import json
import logging
import re
from typing import Any, Mapping, Protocol
from uuid import UUID

from prometheus_client import Counter, Gauge, Histogram

from .worker_config import WorkerSettings


CLAIMED = Counter("smart_alarm_worker_claimed_total", "Claimed outbox events", ("event_type",))
DELIVERIES = Counter("smart_alarm_worker_delivery_total", "Outbox delivery outcomes", ("event_type", "outcome"))
DELIVERY_LATENCY = Histogram("smart_alarm_worker_delivery_seconds", "Outbox handler latency", ("event_type",))
IN_FLIGHT = Gauge("smart_alarm_worker_in_flight", "Outbox events currently handled")
LOOP_FAILURES = Counter("smart_alarm_worker_loop_failures_total", "Worker loop failures", ("error_type",))
LOGGER = logging.getLogger("smart_alarm_bff.worker")


@dataclass(frozen=True, slots=True)
class OutboxEvent:
    event_id: UUID
    tenant_id: UUID | None
    aggregate_type: str
    aggregate_id: str
    event_type: str
    payload: dict[str, object]
    attempts: int
    lease_token: int


class EventHandler(Protocol):
    async def __call__(self, event: OutboxEvent) -> None: ...


class DeliveryError(RuntimeError):
    def __init__(self, code: str, *, retryable: bool = True) -> None:
        if not re.fullmatch(r"[a-z][a-z0-9_]{2,63}", code):
            raise ValueError("delivery error code is invalid")
        super().__init__(code)
        self.code = code
        self.retryable = retryable


def retry_delay(attempts: int, initial_seconds: int, maximum_seconds: int) -> int:
    exponent = max(0, min(attempts - 1, 30))
    return min(maximum_seconds, initial_seconds * (2 ** exponent))


def _payload(value: object) -> dict[str, object]:
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        try:
            decoded = json.loads(value)
        except json.JSONDecodeError as exc:
            raise DeliveryError("invalid_outbox_payload", retryable=False) from exc
        if isinstance(decoded, dict):
            return decoded
    raise DeliveryError("invalid_outbox_payload", retryable=False)


class OutboxRepository:
    def __init__(self, pool: Any) -> None:
        self._pool = pool

    async def claim(self, owner: str, *, limit: int, lease_seconds: int, max_attempts: int) -> list[OutboxEvent]:
        async with self._pool.acquire() as connection:
            async with connection.transaction():
                await connection.execute("SELECT set_config('smart_alarm.system_scope', 'true', true)")
                await connection.execute(
                    """
                    UPDATE smart_alarm.outbox_events
                    SET status = 'DEAD_LETTER', lease_owner = NULL, lease_expires_at = NULL,
                        last_error_code = COALESCE(last_error_code, 'worker_attempts_exhausted')
                    WHERE status IN ('PENDING', 'LEASED') AND attempts >= $1
                      AND (status = 'PENDING' OR lease_expires_at <= clock_timestamp())
                    """,
                    max_attempts,
                )
                rows = await connection.fetch(
                    """
                    WITH candidates AS (
                        SELECT id
                        FROM smart_alarm.outbox_events
                        WHERE attempts < $4
                          AND ((status = 'PENDING' AND next_attempt_at <= clock_timestamp())
                               OR (status = 'LEASED' AND lease_expires_at <= clock_timestamp()))
                        ORDER BY next_attempt_at, created_at, id
                        FOR UPDATE SKIP LOCKED
                        LIMIT $2
                    )
                    UPDATE smart_alarm.outbox_events AS event
                    SET status = 'LEASED', attempts = event.attempts + 1,
                        lease_owner = $1,
                        lease_expires_at = clock_timestamp() + make_interval(secs => $3::double precision),
                        lease_token = event.lease_token + 1,
                        last_error_code = NULL
                    FROM candidates
                    WHERE event.id = candidates.id
                    RETURNING event.id, event.tenant_id, event.aggregate_type, event.aggregate_id,
                              event.event_type, event.payload, event.attempts, event.lease_token
                    """,
                    owner, limit, lease_seconds, max_attempts,
                )
        events: list[OutboxEvent] = []
        for row in rows:
            events.append(OutboxEvent(
                event_id=row["id"],
                tenant_id=row["tenant_id"],
                aggregate_type=row["aggregate_type"],
                aggregate_id=row["aggregate_id"],
                event_type=row["event_type"],
                payload=_payload(row["payload"]),
                attempts=int(row["attempts"]),
                lease_token=int(row["lease_token"]),
            ))
        return events

    async def delivered(self, event: OutboxEvent, owner: str) -> bool:
        return await self._finish(event, owner, "DELIVERED", None, 0)

    async def retry(self, event: OutboxEvent, owner: str, code: str, delay_seconds: int) -> bool:
        return await self._finish(event, owner, "PENDING", code, delay_seconds)

    async def dead_letter(self, event: OutboxEvent, owner: str, code: str) -> bool:
        return await self._finish(event, owner, "DEAD_LETTER", code, 0)

    async def _finish(self, event: OutboxEvent, owner: str, status: str, code: str | None, delay_seconds: int) -> bool:
        async with self._pool.acquire() as connection:
            async with connection.transaction():
                await connection.execute("SELECT set_config('smart_alarm.system_scope', 'true', true)")
                result = await connection.fetchval(
                    """
                    UPDATE smart_alarm.outbox_events
                    SET status = $4, lease_owner = NULL, lease_expires_at = NULL,
                        next_attempt_at = CASE WHEN $4 = 'PENDING'
                            THEN clock_timestamp() + make_interval(secs => $6::double precision)
                            ELSE next_attempt_at END,
                        last_error_code = $5,
                        delivered_at = CASE WHEN $4 = 'DELIVERED' THEN clock_timestamp() ELSE NULL END
                    WHERE id = $1 AND status = 'LEASED' AND lease_owner = $2 AND lease_token = $3
                      AND lease_expires_at > clock_timestamp()
                    RETURNING 1
                    """,
                    event.event_id, owner, event.lease_token, status, code, delay_seconds,
                )
        return result == 1


class OutboxWorker:
    def __init__(
        self,
        settings: WorkerSettings,
        repository: OutboxRepository,
        handlers: Mapping[str, EventHandler],
    ) -> None:
        self._settings = settings
        self._repository = repository
        self._handlers = dict(handlers)

    async def run(self, stop: asyncio.Event) -> None:
        while not stop.is_set():
            try:
                events = await self._repository.claim(
                    self._settings.worker_id,
                    limit=self._settings.batch_size,
                    lease_seconds=self._settings.lease_seconds,
                    max_attempts=self._settings.max_attempts,
                )
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                error_type = type(exc).__name__
                LOOP_FAILURES.labels(error_type).inc()
                LOGGER.warning("outbox claim failed", extra={"error_type": error_type})
                await self._wait(stop)
                continue
            if not events:
                await self._wait(stop)
                continue
            results = await asyncio.gather(*(self.process(event) for event in events), return_exceptions=True)
            for result in results:
                if isinstance(result, asyncio.CancelledError):
                    raise result
                if isinstance(result, BaseException):
                    error_type = type(result).__name__
                    LOOP_FAILURES.labels(error_type).inc()
                    LOGGER.warning("outbox completion failed", extra={"error_type": error_type})

    async def _wait(self, stop: asyncio.Event) -> None:
        try:
            await asyncio.wait_for(stop.wait(), self._settings.poll_interval_ms / 1000)
        except TimeoutError:
            pass

    async def process(self, event: OutboxEvent) -> None:
        CLAIMED.labels(event.event_type).inc()
        IN_FLIGHT.inc()
        handler = self._handlers.get(event.event_type)
        try:
            if handler is None:
                raise DeliveryError("unsupported_event_type", retryable=False)
            with DELIVERY_LATENCY.labels(event.event_type).time():
                async with asyncio.timeout(self._settings.handler_timeout_seconds):
                    await handler(event)
        except asyncio.CancelledError:
            raise
        except TimeoutError:
            await self._failed(event, DeliveryError("handler_timeout"))
        except DeliveryError as exc:
            await self._failed(event, exc)
        except Exception as exc:
            code = f"handler_{type(exc).__name__.lower()}"
            code = re.sub(r"[^a-z0-9_]", "_", code)[:64]
            await self._failed(event, DeliveryError(code))
        else:
            fenced = await self._repository.delivered(event, self._settings.worker_id)
            DELIVERIES.labels(event.event_type, "delivered" if fenced else "fenced").inc()
        finally:
            IN_FLIGHT.dec()

    async def _failed(self, event: OutboxEvent, error: DeliveryError) -> None:
        if error.retryable and event.attempts < self._settings.max_attempts:
            delay = retry_delay(
                event.attempts,
                self._settings.initial_backoff_seconds,
                self._settings.max_backoff_seconds,
            )
            fenced = await self._repository.retry(event, self._settings.worker_id, error.code, delay)
            outcome = "retry" if fenced else "fenced"
        else:
            fenced = await self._repository.dead_letter(event, self._settings.worker_id, error.code)
            outcome = "dead_letter" if fenced else "fenced"
        DELIVERIES.labels(event.event_type, outcome).inc()
