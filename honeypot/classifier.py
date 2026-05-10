"""Classifies captured attacker prompts into attack families."""
from __future__ import annotations

import re
from dataclasses import dataclass


ATTACK_FAMILIES: list[tuple[str, list[str]]] = [
    ("system_prompt_extraction", [
        r"(?i)\b(reveal|show|print|repeat|tell\s+me|what\s+is|share)\b.*\b(system|initial|original|hidden|your)\s+(prompt|instructions?|message)",
        r"(?i)\brepeat\s+the\s+text\s+above\b",
        r"(?i)\bwhat\s+(were\s+)?your\s+(initial\s+)?instructions?",
        r"(?i)\bignore\s+all\s+previous\b.*\b(reveal|show|tell|print)\b",
    ]),
    ("credential_exfiltration", [
        r"(?i)\b(api\s*key|token|password|secret|credential)\b",
        r"(?i)\bcanary\b",
        r"(?i)\bdeploy\s+key\b",
        r"(?i)\bvault\s+code\b",
        r"(?i)\benv(ironment)?\s*(vars?|variables?)\b",
    ]),
    ("role_play_jailbreak", [
        r"(?i)\b(pretend|act\s+as|you\s+are\s+now|imagine\s+you)\b",
        r"(?i)\bDAN\b|\bdo\s+anything\s+now\b",
        r"(?i)\bdeveloper\s+mode\b",
        r"(?i)\bgrandma\s+used\s+to\b",
        r"(?i)\bunrestricted\s+(AI|assistant|model)\b",
    ]),
    ("encoding_obfuscation", [
        r"(?i)\bbase64\b|\brot13\b|\bhex(adecimal)?\b|\bbinary\b",
        r"[A-Za-z0-9+/=]{60,}",  # long base64-looking blob
        r"(?i)\bencoded\b|\bdecode\b|\bcipher\b",
    ]),
    ("multilingual_evasion", [
        r"[\u4e00-\u9fff]+",  # CJK
        r"[\u0600-\u06ff]+",  # Arabic
        r"[\u0400-\u04ff]+",  # Cyrillic
        r"(?i)\bin\s+(spanish|french|german|chinese|russian|arabic|korean|japanese)\b",
    ]),
    ("ignore_override", [
        r"(?i)\bignore\s+(all|every|the)\s+(previous|prior|above)\b",
        r"(?i)\bdisregard\s+(all|every|previous)\b",
        r"(?i)\bforget\s+(everything|all|your)\b",
        r"(?i)\boverride\b.*\b(rules?|instructions?|guidelines?)\b",
    ]),
    ("recon_probing", [
        r"(?i)\bwhat\s+(model|version|company)\s+(are|made)\s+you\b",
        r"(?i)\bwho\s+(created|made|built|trained)\s+you\b",
        r"(?i)\bwhat\s+can\s+you\s+(do|access)\b",
        r"(?i)\blist\s+your\s+(tools|capabilities|functions)\b",
    ]),
    ("data_exfiltration_via_url", [
        r"https?://[^\s]+\?[^\s]*=",  # URL with query for exfil
        r"(?i)\bcurl\b|\bwget\b|\bfetch\b|\brequests?\.get\b",
    ]),
    ("xml_html_injection", [
        r"<\s*\|?\s*(im_start|im_end|system|admin|s>)\s*\|?\s*>",
        r"\[INST\]|\[/INST\]",
        r"<\|begin_of_text\|>|<\|end_of_text\|>",
    ]),
]


@dataclass
class AttackClassification:
    families: list[str]
    confidence: float
    canary_attempted: bool
    notes: list[str]

    def to_dict(self) -> dict:
        return {
            "families": self.families,
            "confidence": round(self.confidence, 3),
            "canary_attempted": self.canary_attempted,
            "notes": self.notes,
        }


def classify(prompt: str, canary_tokens: list[str] | None = None) -> AttackClassification:
    families: list[str] = []
    notes: list[str] = []
    for family, patterns in ATTACK_FAMILIES:
        for pat in patterns:
            if re.search(pat, prompt):
                if family not in families:
                    families.append(family)
                break
    canary_attempted = False
    if canary_tokens:
        for c in canary_tokens:
            if c.lower() in prompt.lower() or any(
                p.lower() in prompt.lower() for p in c.split("-")[:2]
            ):
                canary_attempted = True
                notes.append(f"canary token referenced: {c[:20]}")
                break
    confidence = min(1.0, 0.25 * len(families) + (0.3 if canary_attempted else 0))
    return AttackClassification(families, confidence, canary_attempted, notes)


def fingerprint(prompt: str) -> str:
    """Simple SHA1 fingerprint for dedup, normalized."""
    import hashlib
    norm = re.sub(r"\s+", " ", prompt.lower().strip())
    return hashlib.sha1(norm.encode()).hexdigest()[:16]
