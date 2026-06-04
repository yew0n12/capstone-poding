from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict

from engine.models import Event, parse_time


ROLLING_DELAY_WINDOW_SIZE = 1000
MIN_ADAPTIVE_DELTA_SECONDS = 10.0
MIN_MARGIN_SECONDS = 5.0
MAX_MARGIN_SECONDS = 10.0
# Floor for inversion tolerance. The estimator returns at least this much so
# that two roughly-simultaneous events with a tiny clock skew never get
# rejected even when no delay samples have been collected yet.
SMALL_BACK_TOLERANCE_SECONDS = 2.0


@dataclass
class DelayEstimator:
    window_size: int = ROLLING_DELAY_WINDOW_SIZE
    samples: Dict[str, list[float]] = field(default_factory=dict)

    def add(self, *, source: str, delay_seconds: float) -> None:
        bucket = self.samples.setdefault(source, [])
        bucket.append(max(0.0, delay_seconds))
        if len(bucket) > self.window_size:
            del bucket[: -self.window_size]

    def percentile(self, source: str, percentile: float) -> float:
        values = sorted(self.samples.get(source, []))
        if not values:
            return 0.0
        if len(values) == 1:
            return values[0]
        percentile = min(100.0, max(0.0, percentile))
        index = int(round((percentile / 100.0) * (len(values) - 1)))
        return values[index]

    def summary(self, source: str) -> Dict[str, float | int]:
        values = self.samples.get(source, [])
        return {
            "count": len(values),
            "p50": self.percentile(source, 50.0),
            "p90": self.percentile(source, 90.0),
            "p95": self.percentile(source, 95.0),
        }

    def add_event(self, event: Event) -> float | None:
        delay = compute_event_delay(event)
        if delay is None:
            return None
        self.add(source=event.event_source, delay_seconds=delay)
        return delay

    def small_back_tolerance(self) -> float:
        # Inversion happens because one sensor lags more than the other, so the
        # tolerance only needs to cover the skew between them, not the full
        # delta_s_e chain window. Floor at SMALL_BACK_TOLERANCE_SECONDS so a
        # cold estimator still permits tiny clock-skew inversions.
        p95_falco = self.percentile("falco", 95.0)
        p95_hubble = self.percentile("hubble", 95.0)
        skew = abs(p95_falco - p95_hubble)
        margin = min(MAX_MARGIN_SECONDS, max(MIN_MARGIN_SECONDS, 0.1 * skew))
        return max(SMALL_BACK_TOLERANCE_SECONDS, skew + margin)

    def model(self) -> Dict[str, Any]:
        falco = self.summary("falco")
        hubble = self.summary("hubble")
        p95_falco = float(falco["p95"])
        p95_hubble = float(hubble["p95"])
        margin = min(
            MAX_MARGIN_SECONDS,
            max(MIN_MARGIN_SECONDS, 0.1 * (p95_falco + p95_hubble)),
        )
        delta = max(MIN_ADAPTIVE_DELTA_SECONDS, p95_falco + p95_hubble + margin)
        return {
            "falco": falco,
            "hubble": hubble,
            "estimated_p95_delay_falco": p95_falco,
            "estimated_p95_delay_hubble": p95_hubble,
            "skew_estimate": p95_falco - p95_hubble,
            "margin_seconds": margin,
            "delta_s_e": delta,
            "delta_e_follow": delta,
            "small_back_tolerance_seconds": self.small_back_tolerance(),
        }


def compute_event_delay(event: Event) -> float | None:
    if not event.ingested_at:
        return None
    try:
        ingested = parse_time(event.ingested_at)
    except Exception:
        return None
    return max(0.0, (ingested - event.observed_at).total_seconds())
