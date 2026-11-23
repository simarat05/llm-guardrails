from abc import ABC, abstractmethod
from enum import Enum
from pydantic import BaseModel


class Action(str, Enum):
    ALLOW = "allow"
    BLOCK = "block"
    MASK = "mask"
    WARN = "warn"


class Verdict(BaseModel):
    guard: str
    passed: bool
    score: float = 0.0
    reason: str = ""
    action: Action = Action.ALLOW
    modified_text: str | None = None


class Guard(ABC):
    name: str = "base"

    @abstractmethod
    def check(self, text: str) -> Verdict:
        ...