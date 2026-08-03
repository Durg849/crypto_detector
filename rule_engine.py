"""
rule_engine.py
────────────────────────────────────────────────────────────────────────────
Layer 1 of Injecto's detection pipeline: fast, deterministic pattern
matching against known prompt-injection techniques.

The original version of this file only matched ~17 plain-English phrases
("ignore previous instructions", "act as dan", ...). That catches nothing
that isn't typed in exactly that form, and misses the categories that
actually show up in 2025/2026 attacks:

  1. Plain-language instruction override / jailbreak phrasing (the old set,
     expanded — including newer persona names and "hypothetical framing"
     bypasses that ask the model to roleplay past its own rules).
  2. Structural / delimiter attacks — fake "[SYSTEM]" or "###Instruction###"
     blocks, ChatML-style tags, "-- END OF PROMPT --" markers, trying to
     get the model to treat user text as a new system message.
  3. Encoding / obfuscation smuggling — base64 or hex blobs, zero-width
     and other invisible Unicode characters, homoglyph substitution
     (Cyrillic/fullwidth lookalikes) used to sneak a banned phrase past a
     literal string match. We normalize input before matching, and also
     opportunistically decode base64/hex blobs and re-scan the decoded
     text.
  4. Exfiltration imperatives — "send this to", "POST this to", embedded
     URLs paired with secret-sounding nouns, which matter most for
     indirect injection (attack text arriving via a fetched document
     rather than typed by the user).
  5. Multilingual variants of the core override phrases, since a rule
     engine that only understands English is trivial to route around.

This is still a *keyword/pattern* layer — it's meant to be fast and cheap,
catching the "low-effort" attacks so the ML layer and Pipelock only have to
work on the harder cases. It is not, and isn't meant to be, a complete
defense on its own.
"""

import base64
import binascii
import re
import unicodedata
from dataclasses import dataclass, field
from typing import List, Tuple


# ─── Hardcoded firewall (bypasses everything else, always blocks) ──────────

FIREWALL_WORDS = [
    "reveal password", "show api key", "system secret", "database password",
    "dump environment variables", "print .env",
]


# ─── Pattern categories ──────────────────────────────────────────────────────
# Each category maps to a severity weight (0-100) used in risk scoring, and
# a list of (regex, attack_type_label) pairs. Patterns are matched against
# normalized (lowercased, de-obfuscated) text.

_INSTRUCTION_OVERRIDE = [
    (r"\bignore (all|the|any|previous|prior|above|earlier)\b.{0,30}\b(instructions?|rules?|guidelines?|prompts?)\b", "Instruction Override"),
    (r"\bdisregard\b.{0,30}\b(instructions?|rules?|guidelines?|prompt)\b", "Instruction Override"),
    (r"\bforget (your|all|the|any)\b.{0,20}\b(training|instructions?|rules?|guidelines?)\b", "Training Override"),
    (r"\boverride\b.{0,20}\b(rules?|instructions?|settings?|restrictions?)\b", "Rule Override"),
    (r"\bstart (over|fresh|from scratch)\b.{0,20}\bignor", "Instruction Override"),
    (r"\bnew (instructions?|rules?|directive)\b.{0,10}\b(follow|obey|override)\b", "Instruction Override"),
]

_PROMPT_LEAKING = [
    (r"\breveal\b.{0,20}\b(system prompt|instructions?|hidden prompt|configuration)\b", "Prompt Leaking"),
    (r"\b(show|print|output|repeat|display)\b.{0,20}\b(system prompt|your instructions|initial prompt)\b", "Prompt Leaking"),
    (r"\bwhat (were|are) your (original )?instructions\b", "Prompt Leaking"),
    (r"\brepeat (the words|everything) (above|before this)\b", "Prompt Leaking"),
    (r"\bsummarize (the|your) (system prompt|instructions above)\b", "Prompt Leaking"),
]

_ROLE_HIJACKING = [
    (r"\byou are now\b", "Role Hijacking"),
    (r"\bpretend (that )?you are\b", "Role Hijacking"),
    (r"\bact as (system|admin|root|developer|an unrestricted)\b", "Privilege Escalation"),
    (r"\bfrom now on,? you\b.{0,20}\b(are|will be|must)\b", "Role Hijacking"),
    (r"\bswitch (to|into)\b.{0,15}\bpersona\b", "Persona Injection"),
    (r"\bnew persona\b", "Persona Injection"),
    (r"\byou have no (rules|restrictions|limitations|filters)\b", "Restriction Bypass"),
    (r"\bwithout (any )?(restrictions?|limitations?|filters?|censorship)\b", "Restriction Bypass"),
]

# Known jailbreak persona / mode names. These are widely documented in
# public security research (OWASP LLM Top 10 writeups, red-team reports) —
# listing them for a blocklist is standard defensive practice, the same way
# antivirus signatures name known malware families.
_JAILBREAK_PERSONAS = [
    (r"\bdan\b.{0,15}\b(do anything now|mode|jailbreak)\b", "Jailbreak Attack"),
    (r"\bdo anything now\b", "Jailbreak Attack"),
    (r"\b(stan|aim|dude|dude-gpt)\b.{0,15}\bmode\b", "Jailbreak Attack"),
    (r"\bdeveloper mode\b", "Developer Mode Exploit"),
    (r"\bgod mode\b", "Jailbreak Attack"),
    (r"\bsudo mode\b", "Privilege Escalation"),
    (r"\bopposite (day|mode)\b", "Jailbreak Attack"),
    (r"\bevil (twin|confidant|assistant)\b", "Jailbreak Attack"),
    (r"\bjailbreak(ed|ing)?\b", "Jailbreak Attack"),
]

_SAFETY_BYPASS = [
    (r"\bbypass\b.{0,20}\b(safety|filters?|restrictions?|content policy|guardrails?)\b", "Safety Bypass"),
    (r"\bdisable\b.{0,20}\b(restrictions?|safety|filters?|guardrails?|content policy)\b", "Restriction Bypass"),
    (r"\bturn off\b.{0,15}\b(safety|filters?|moderation|guardrails?)\b", "Safety Bypass"),
    (r"\bno (content )?filter(ing)?\b", "Safety Bypass"),
    (r"\bunfiltered\b.{0,15}\b(response|answer|ai|mode)\b", "Safety Bypass"),
]

# "Hypothetical framing" — asking the model to roleplay, write fiction, or
# treat something as a thought experiment specifically to route around its
# guidelines. The giveaway is pairing the hypothetical/fictional framing
# with an explicit reference to rules, guidelines, or restrictions.
_HYPOTHETICAL_FRAMING = [
    (r"\bhypothetically\b.{0,40}\b(no rules|ignore|without restrictions|guidelines)\b", "Hypothetical Framing Bypass"),
    (r"\bfor (research|educational|academic) purposes\b.{0,40}\b(ignore|bypass|no restrictions)\b", "Hypothetical Framing Bypass"),
    (r"\bin (a|this) fictional (world|story|scenario)\b.{0,40}\b(no rules|anything|unrestricted)\b", "Hypothetical Framing Bypass"),
    (r"\bthis is (just|only) a (game|simulation|roleplay)\b.{0,40}\b(rules don'?t apply|no limits)\b", "Hypothetical Framing Bypass"),
]

# Structural / delimiter attacks — trying to make the model treat injected
# text as a new system/assistant message rather than user content.
_STRUCTURAL = [
    (r"\[\s*system\s*\]", "Delimiter Injection"),
    (r"<\s*/?\s*system\s*>", "Delimiter Injection"),
    (r"<<\s*sys\s*>>", "Delimiter Injection"),
    (r"###\s*instructions?\s*###", "Delimiter Injection"),
    (r"---+\s*end of (prompt|system message|instructions)\s*---+", "Delimiter Injection"),
    (r"\bassistant\s*:\s*$", "Delimiter Injection"),
    (r"\bsystem\s*:\s*you (are|must|will)\b", "Delimiter Injection"),
    (r"```\s*system\b", "Delimiter Injection"),
]

# Exfiltration imperatives — mostly relevant for indirect injection (text
# arriving via a fetched webpage/document rather than typed by the user).
_EXFILTRATION = [
    (r"\bsend\b.{0,25}\b(api key|password|token|secret|credentials?)\b.{0,25}\bto\b", "Exfiltration Attempt"),
    (r"\b(post|curl|fetch)\b.{0,15}https?://\S+.{0,25}\b(key|token|secret|password)\b", "Exfiltration Attempt"),
    (r"\bemail (this|the (data|results?|output)) to\b", "Exfiltration Attempt"),
    (r"\binclude (your|the) (api key|credentials?|token) in\b", "Exfiltration Attempt"),
]

# A handful of common non-English renderings of the core override phrases,
# so the engine isn't trivially bypassed by switching languages. Not
# exhaustive — the ML layer is expected to catch what this misses.
_MULTILINGUAL = [
    (r"ignora (las |todas )*instrucciones anteriores", "Instruction Override (ES)"),
    (r"ignorez? (les |toutes )?instructions précédentes", "Instruction Override (FR)"),
    (r"ignorier[e]? (die )?vorherigen anweisungen", "Instruction Override (DE)"),
    (r"忽略(之前|上面)的指令", "Instruction Override (ZH)"),
    (r"actúa como (el sistema|administrador)", "Role Hijacking (ES)"),
]

CATEGORY_WEIGHTS = {
    "instruction_override": 75,
    "prompt_leaking": 75,
    "role_hijacking": 70,
    "jailbreak_persona": 80,
    "safety_bypass": 80,
    "hypothetical_framing": 60,
    "structural": 85,
    "exfiltration": 90,
    "multilingual": 75,
    "obfuscation": 65,  # bonus weight when normalization had to do work
}

_PATTERN_GROUPS: List[Tuple[str, List[Tuple[str, str]]]] = [
    ("instruction_override", _INSTRUCTION_OVERRIDE),
    ("prompt_leaking", _PROMPT_LEAKING),
    ("role_hijacking", _ROLE_HIJACKING),
    ("jailbreak_persona", _JAILBREAK_PERSONAS),
    ("safety_bypass", _SAFETY_BYPASS),
    ("hypothetical_framing", _HYPOTHETICAL_FRAMING),
    ("structural", _STRUCTURAL),
    ("exfiltration", _EXFILTRATION),
    ("multilingual", _MULTILINGUAL),
]

_COMPILED_GROUPS = [
    (category, [(re.compile(rx, re.IGNORECASE), label) for rx, label in patterns])
    for category, patterns in _PATTERN_GROUPS
]


# ─── Normalization ───────────────────────────────────────────────────────────
# Strip the tricks people use to sneak a banned phrase past a literal string
# match: zero-width characters, homoglyphs, and simple case/whitespace games.

_ZERO_WIDTH = "".join([
    "\u200b",  # zero-width space
    "\u200c",  # zero-width non-joiner
    "\u200d",  # zero-width joiner
    "\ufeff",  # BOM / zero-width no-break space
    "\u2060",  # word joiner
])
_ZERO_WIDTH_RE = re.compile(f"[{_ZERO_WIDTH}]")

# Common homoglyphs seen in obfuscated jailbreak text: Cyrillic/Greek
# lookalikes and fullwidth Unicode forms mapped back to plain ASCII.
_HOMOGLYPHS = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x",  # Cyrillic
    "і": "i", "ѕ": "s", "ԁ": "d", "ց": "g", "ⅰ": "i",
    "０": "0", "１": "1", "２": "2", "３": "3", "４": "4",
    "５": "5", "６": "6", "７": "7", "８": "8", "９": "9",
}


def _fold_homoglyphs(text: str) -> str:
    return "".join(_HOMOGLYPHS.get(ch, ch) for ch in text)


def _fullwidth_to_ascii(text: str) -> str:
    # NFKC normalization collapses most fullwidth/compatibility forms
    # (e.g. fullwidth Latin letters) down to their ASCII equivalents.
    return unicodedata.normalize("NFKC", text)


def _try_decode_blobs(text: str) -> str:
    """
    Opportunistically decode base64/hex blobs embedded in the prompt and
    append the decoded text so patterns can match against it too. This is
    deliberately permissive (short blobs, decode failures) since a false
    positive here just means we scan a bit of garbage text, not a false
    block — the caller still needs a real pattern match downstream.
    """
    decoded_chunks = []

    for match in re.finditer(r"[A-Za-z0-9+/]{24,}={0,2}", text):
        candidate = match.group(0)
        try:
            decoded = base64.b64decode(candidate, validate=True)
            decoded_text = decoded.decode("utf-8", errors="ignore")
            if decoded_text.isprintable() and len(decoded_text) > 8:
                decoded_chunks.append(decoded_text)
        except (binascii.Error, ValueError):
            pass

    for match in re.finditer(r"(?:[0-9a-fA-F]{2}){8,}", text):
        candidate = match.group(0)
        try:
            decoded = bytes.fromhex(candidate)
            decoded_text = decoded.decode("utf-8", errors="ignore")
            if decoded_text.isprintable() and len(decoded_text) > 8:
                decoded_chunks.append(decoded_text)
        except ValueError:
            pass

    return " ".join(decoded_chunks)


def normalize(prompt: str) -> Tuple[str, bool]:
    """
    Returns (normalized_text, was_obfuscated). was_obfuscated is True if we
    found and stripped zero-width characters or homoglyphs — that's itself
    a mild signal, since legitimate prompts essentially never contain them.
    """
    had_zero_width = bool(_ZERO_WIDTH_RE.search(prompt))
    stripped = _ZERO_WIDTH_RE.sub("", prompt)

    folded = _fold_homoglyphs(stripped)
    had_homoglyphs = folded != stripped

    ascii_normalized = _fullwidth_to_ascii(folded)
    decoded_extra = _try_decode_blobs(prompt)

    combined = (ascii_normalized + " " + decoded_extra).lower()
    was_obfuscated = had_zero_width or had_homoglyphs or bool(decoded_extra)
    return combined, was_obfuscated


# ─── Result type ─────────────────────────────────────────────────────────────

@dataclass
class RuleResult:
    safe: bool
    blocked_by_firewall: bool
    patterns: List[str] = field(default_factory=list)          # raw regex descriptions, for debugging
    attack_types: List[str] = field(default_factory=list)
    categories: List[str] = field(default_factory=list)
    obfuscation_detected: bool = False
    risk_score: int = 10
    reason: str = "Prompt is safe"

    def to_dict(self) -> dict:
        return {
            "safe": self.safe,
            "blocked_by_firewall": self.blocked_by_firewall,
            "patterns": self.patterns,
            "attack_types": self.attack_types,
            "categories": self.categories,
            "obfuscation_detected": self.obfuscation_detected,
            "risk_score": self.risk_score,
            "reason": self.reason,
        }


# ─── Core logic ──────────────────────────────────────────────────────────────

def firewall_check(prompt: str) -> bool:
    """Hardcoded, non-negotiable blocklist. Bypasses everything else."""
    lowered = prompt.lower()
    return any(w in lowered for w in FIREWALL_WORDS)


def detect_injection(prompt: str):
    """
    Runs every pattern category against normalized text. Returns
    (matched_patterns, attack_types, categories_hit, was_obfuscated).
    """
    normalized_text, was_obfuscated = normalize(prompt)

    matched_patterns = []
    attack_types = []
    categories_hit = []

    for category, compiled_patterns in _COMPILED_GROUPS:
        for regex, label in compiled_patterns:
            m = regex.search(normalized_text)
            if m:
                matched_patterns.append(m.group(0).strip())
                attack_types.append(label)
                if category not in categories_hit:
                    categories_hit.append(category)

    return matched_patterns, list(dict.fromkeys(attack_types)), categories_hit, was_obfuscated


def calculate_risk(categories_hit: List[str], was_obfuscated: bool) -> int:
    if not categories_hit:
        return 15 if was_obfuscated else 10  # invisible chars alone is mildly suspicious

    base = max(CATEGORY_WEIGHTS.get(c, 50) for c in categories_hit)
    # Multiple distinct attack categories in one prompt is a stronger signal
    # than one category matched several times.
    stacking_bonus = min(15, (len(categories_hit) - 1) * 5)
    obfuscation_bonus = 10 if was_obfuscated else 0
    return min(100, base + stacking_bonus + obfuscation_bonus)


def severity_level(risk: int) -> str:
    if risk < 30:
        return "LOW"
    elif risk < 70:
        return "MEDIUM"
    return "HIGH"


def analyze(prompt: str) -> RuleResult:
    """Run the rule-based layer over a prompt and return a RuleResult."""
    if firewall_check(prompt):
        return RuleResult(
            safe=False,
            blocked_by_firewall=True,
            patterns=[],
            attack_types=["Firewall Block"],
            categories=["firewall"],
            risk_score=100,
            reason="Prompt contains forbidden content",
        )

    patterns, attack_types, categories_hit, was_obfuscated = detect_injection(prompt)
    risk = calculate_risk(categories_hit, was_obfuscated)
    detected = len(categories_hit) > 0

    reason = "Prompt is safe"
    if detected:
        reason = "Prompt injection detected"
    elif was_obfuscated:
        reason = "No known pattern matched, but prompt contains obfuscated/invisible characters"

    return RuleResult(
        safe=not detected,
        blocked_by_firewall=False,
        patterns=patterns,
        attack_types=attack_types,
        categories=categories_hit,
        obfuscation_detected=was_obfuscated,
        risk_score=risk,
        reason=reason,
    )
