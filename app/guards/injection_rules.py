import re
from .base import Guard, Verdict, Action

# Each rule: (name, compiled pattern, weight)
RULES = [
    ("ignore_instructions",
     re.compile(r"\b(ignore|disregard|forget|override)\b.{0,30}\b(previous|prior|above|earlier|all|your)\b.{0,30}\b(instructions?|prompts?|rules?|directions?)\b", re.I), 0.9),
    ("reveal_system_prompt",
     re.compile(r"\b(reveal|show|print|repeat|leak|display)\b.{0,30}\b(system|hidden|initial|original)\b.{0,15}\b(prompt|instructions?|message)\b", re.I), 0.9),
    ("role_override",
     re.compile(r"\b(you are now|act as|pretend (to be|you are)|from now on you)\b", re.I), 0.5),
    ("jailbreak_persona",
     re.compile(r"\b(DAN|do anything now|developer mode|jailbreak(ed)?)\b", re.I), 0.8),
    ("bypass_safety",
     re.compile(r"\b(bypass|disable|turn off|remove)\b.{0,20}\b(safety|filters?|guardrails?|restrictions?|rules)\b", re.I), 0.8),
    ("fake_system_tag",
     re.compile(r"(\[/?(system|inst)\]|<\|?(system|im_start)\|?>|###\s*system)", re.I), 0.7),
]


class RuleInjectionGuard(Guard):
    name = "injection_rules"

    def __init__(self, threshold: float = 0.7):
        self.threshold = threshold

    def check(self, text: str) -> Verdict:
        hits = [(n, w) for n, p, w in RULES if p.search(text)]
        if not hits:
            return Verdict(guard=self.name, passed=True)

        score = min(1.0, max(w for _, w in hits) + 0.1 * (len(hits) - 1))
        passed = score < self.threshold
        return Verdict(
            guard=self.name,
            passed=passed,
            score=round(score, 2),
            reason="Matched: " + ", ".join(n for n, _ in hits),
            action=Action.ALLOW if passed else Action.BLOCK,
        )