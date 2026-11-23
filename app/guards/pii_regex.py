import re
from .base import Guard, Verdict, Action

PATTERNS = {
    "AADHAAR": re.compile(r"(?<!\d)[2-9]\d{3}\s?\d{4}\s?\d{4}(?!\d)"),
    "PAN": re.compile(r"\b[A-Z]{5}[0-9]{4}[A-Z]\b"),
    "EMAIL": re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b"),
    "PHONE": re.compile(r"(?<!\d)(?:\+91[\s-]?)?[6-9]\d{9}(?!\d)"),
}


class RegexPIIGuard(Guard):
    name = "pii_regex"

    def check(self, text: str) -> Verdict:
        masked = text
        found = []
        for label, pattern in PATTERNS.items():
            masked, n = pattern.subn(f"[{label}]", masked)
            if n:
                found.append(f"{label} x{n}")

        if not found:
            return Verdict(guard=self.name, passed=True)

        return Verdict(
            guard=self.name,
            passed=False,
            score=1.0,
            reason="Detected: " + ", ".join(found),
            action=Action.MASK,
            modified_text=masked,
        )