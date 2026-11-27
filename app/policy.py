from pathlib import Path
import yaml
from pydantic import BaseModel
from .pipeline import Pipeline
from .guards.base import Guard
from .guards.pii_regex import RegexPIIGuard
from .guards.injection_rules import RuleInjectionGuard

DEFAULT_POLICY = Path(__file__).resolve().parent.parent / "config" / "policy.yaml"


class GuardConfig(BaseModel):
    guard: str
    enabled: bool = True
    threshold: float | None = None


class PipelineConfig(BaseModel):
    short_circuit: bool = True


class Policy(BaseModel):
    pipeline: PipelineConfig = PipelineConfig()
    input: list[GuardConfig] = []


def _build_guard(cfg: GuardConfig) -> Guard:
    kwargs = {} if cfg.threshold is None else {"threshold": cfg.threshold}

    if cfg.guard == "pii_regex":
        return RegexPIIGuard()
    if cfg.guard == "injection_rules":
        return RuleInjectionGuard(**kwargs)
    if cfg.guard == "injection_classifier":
        # Imported here so torch/transformers only load when this guard is enabled
        from .guards.injection_classifier import ClassifierInjectionGuard
        return ClassifierInjectionGuard(**kwargs)
    raise ValueError(f"Unknown guard in policy: {cfg.guard}")


def load_pipeline(path=DEFAULT_POLICY) -> Pipeline:
    with open(path, encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    policy = Policy(**data)
    guards = [_build_guard(g) for g in policy.input if g.enabled]
    return Pipeline(guards, short_circuit=policy.pipeline.short_circuit)