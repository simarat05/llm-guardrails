import time
from pydantic import BaseModel
from .guards.base import Guard, Verdict, Action


class PipelineResult(BaseModel):
    allowed: bool
    final_text: str
    verdicts: list[Verdict]
    blocked_by: str | None = None
    timings_ms: dict[str, float] = {}
    total_ms: float = 0.0


class Pipeline:
    def __init__(self, guards: list[Guard], short_circuit: bool = True):
        self.guards = guards
        self.short_circuit = short_circuit

    def run(self, text: str) -> PipelineResult:
        current = text
        verdicts: list[Verdict] = []
        timings: dict[str, float] = {}
        blocked_by = None
        start = time.perf_counter()

        for guard in self.guards:
            t0 = time.perf_counter()
            v = guard.check(current)
            timings[guard.name] = round((time.perf_counter() - t0) * 1000, 2)
            verdicts.append(v)

            # Masking changes the text that later guards see
            if v.action == Action.MASK and v.modified_text is not None:
                current = v.modified_text

            if v.action == Action.BLOCK and not v.passed:
                blocked_by = blocked_by or guard.name
                if self.short_circuit:
                    break

        return PipelineResult(
            allowed=blocked_by is None,
            final_text=current,
            verdicts=verdicts,
            blocked_by=blocked_by,
            timings_ms=timings,
            total_ms=round((time.perf_counter() - start) * 1000, 2),
        )