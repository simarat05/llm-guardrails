from transformers import pipeline
from .base import Guard, Verdict, Action

MODEL_ID = "protectai/deberta-v3-base-prompt-injection-v2"


class ClassifierInjectionGuard(Guard):
    name = "injection_classifier"

    def __init__(self, threshold: float = 0.5, model_id: str = MODEL_ID):
        self.threshold = threshold
        # Loads once, so create one guard instance and reuse it
        self.clf = pipeline(
            "text-classification",
            model=model_id,
            truncation=True,
            max_length=512,
        )

    def check(self, text: str) -> Verdict:
        result = self.clf(text)[0]
        # This model's labels are "INJECTION" and "SAFE"
        p_inject = result["score"] if result["label"] == "INJECTION" else 1 - result["score"]
        passed = p_inject < self.threshold
        return Verdict(
            guard=self.name,
            passed=passed,
            score=round(p_inject, 3),
            reason="" if passed else f"Injection probability {p_inject:.2f}",
            action=Action.ALLOW if passed else Action.BLOCK,
        )