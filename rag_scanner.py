"""
rag_scanner.py
────────────────────────────────────────────────────────────────────────────
Layer for Injecto's indirect-injection detection: scans content that
arrives via RAG retrieval (documents, chunks, tool outputs) BEFORE it is
concatenated into the LLM's context window.

This is a different threat surface than direct prompt scanning:
  - The attacker never talks to your app. They plant text in a document
    that they know (or hope) your pipeline will retrieve and hand to the
    model — a wiki page, a support ticket, a PDF, a web page, a product
    review, an email your agent reads.
  - The payload doesn't need to look like a "prompt" at all. It just needs
    to look like an instruction *to the model* once it's sitting in context.
  - It can be hidden from human reviewers (invisible HTML/PDF text) while
    still being fully visible to the model.

Reuses rule_engine.analyze() and obfuscation_detector.deobfuscate() for the
actual pattern matching, and adds detectors + scoring specific to
third-party retrieved content.

Usage:
    from rag_scanner import scan_document, scan_retrieval_set

    result = scan_document(chunk_text, source="https://example.com/page",
                            source_trust="unverified")
    if not result.safe:
        ...  # block, redact, or quarantine this chunk

    batch = scan_retrieval_set([
        {"text": c1, "source": "kb://internal/doc1", "source_trust": "verified"},
        {"text": c2, "source": "https://random-blog.com/x", "source_trust": "unverified"},
    ])
"""

import re
from dataclasses import dataclass, field
from typing import List, Dict, Optional

import rule_engine
import obfuscation_detector


# ─── Source trust weighting ──────────────────────────────────────────────────
# Same content scores higher risk from a source you don't control. This is
# a multiplier applied on top of the base pattern-match risk, not a
# replacement for it — an untrusted source with zero pattern hits is still
# "safe", just scanned with a slightly lower bar for the stacking bonus.

TRUST_MULTIPLIERS = {
    "verified": 0.85,     # your own curated KB, signed/internal content
    "internal": 1.0,      # internal but not curated (e.g. employee uploads)
    "unverified": 1.15,   # open web, third-party APIs, user-submitted docs
    "untrusted": 1.3,     # explicitly flagged sources, public scrape targets
}

DEFAULT_TRUST = "unverified"

# ─── Imperative-in-content detector ──────────────────────────────────────────
# Content that shouldn't be issuing instructions, doing so, is the core
# signature of indirect injection. This looks for imperative phrasing
# directed at "the AI / assistant / model" rather than at a human reader —
# distinct from rule_engine's direct-override patterns, which assume the
# text IS the prompt rather than a review/ticket/page ABOUT something else.

_THIRD_PARTY_IMPERATIVES = [
    (r"\b(ai|assistant|model|chatbot|llm)\b.{0,20}\b(should|must|will now|is instructed to)\b", "Third-Party Directive"),
    (r"\bwhen (you|the ai|the assistant) (read|process|summarize)s? this\b", "Conditional Trigger"),
    (r"\bif you are (an ai|a language model|reading this as an assistant)\b", "AI-Targeted Trigger"),
    (r"\bnote to (ai|assistant|model|reader)\s*:", "Embedded Directive"),
    (r"\b(do not|don'?t) (mention|tell|inform|reveal)\b.{0,30}\b(user|human|this instruction)\b", "Concealment Instruction"),
    (r"\bafter summarizing,?\s*(also |then )?(send|email|post|forward)\b", "Post-Action Exfiltration"),
]
_COMPILED_IMPERATIVES = [(re.compile(rx, re.IGNORECASE), label) for rx, label in _THIRD_PARTY_IMPERATIVES]


def detect_third_party_imperatives(text: str) -> List[str]:
    hits = []
    for regex, label in _COMPILED_IMPERATIVES:
        if regex.search(text):
            hits.append(label)
    return hits


# ─── Hidden-text detection (HTML/Markdown sources) ──────────────────────────
# Catches the classic "white text on white background" / display:none /
# font-size:0 / off-screen-position tricks used to hide a payload from a
# human skimming the page while leaving it fully readable to the model
# that ingests raw text or DOM content. Works on HTML/markdown source;
# for PDFs, hidden text should be flagged upstream during extraction
# (layer order + render-invisible glyphs), which needs the raw PDF object,
# not just extracted text — flag that separately if your ingestion pipeline
# exposes it.

_HIDDEN_TEXT_PATTERNS = [
    re.compile(r"style\s*=\s*['\"][^'\"]*display\s*:\s*none", re.IGNORECASE),
    re.compile(r"style\s*=\s*['\"][^'\"]*visibility\s*:\s*hidden", re.IGNORECASE),
    re.compile(r"style\s*=\s*['\"][^'\"]*font-size\s*:\s*0", re.IGNORECASE),
    re.compile(r"style\s*=\s*['\"][^'\"]*color\s*:\s*#?(fff|ffffff|white)[^'\"]*background(-color)?\s*:\s*#?(fff|ffffff|white)", re.IGNORECASE),
    re.compile(r"<!--.*?-->", re.DOTALL),   # HTML comments can carry payloads invisibly
    re.compile(r"aria-hidden\s*=\s*['\"]true['\"]", re.IGNORECASE),
]


def detect_hidden_text_markup(raw_html_or_markdown: str) -> List[str]:
    """
    Scans raw markup (not the extracted/rendered text) for techniques used
    to hide content from a human reader. Call this on the source HTML
    before text-extraction strips the formatting away.
    """
    found = []
    for pattern in _HIDDEN_TEXT_PATTERNS:
        matches = pattern.findall(raw_html_or_markdown)
        if matches:
            found.append(pattern.pattern[:40])
    return found


# ─── Result types ────────────────────────────────────────────────────────────

@dataclass
class ChunkScanResult:
    safe: bool
    source: str
    source_trust: str
    risk_score: int
    severity: str
    attack_types: List[str] = field(default_factory=list)
    patterns: List[str] = field(default_factory=list)
    third_party_directives: List[str] = field(default_factory=list)
    hidden_text_techniques: List[str] = field(default_factory=list)
    obfuscation_detected: bool = False
    recommended_action: str = "allow"   # allow | redact | quarantine | block
    reason: str = ""

    def to_dict(self) -> dict:
        return {
            "safe": self.safe,
            "source": self.source,
            "source_trust": self.source_trust,
            "risk_score": self.risk_score,
            "severity": self.severity,
            "attack_types": self.attack_types,
            "patterns": self.patterns,
            "third_party_directives": self.third_party_directives,
            "hidden_text_techniques": self.hidden_text_techniques,
            "obfuscation_detected": self.obfuscation_detected,
            "recommended_action": self.recommended_action,
            "reason": self.reason,
        }


@dataclass
class RetrievalSetResult:
    safe: bool
    chunk_results: List[ChunkScanResult]
    aggregate_risk: int
    stacking_flag: bool
    flagged_chunk_count: int

    def to_dict(self) -> dict:
        return {
            "safe": self.safe,
            "aggregate_risk": self.aggregate_risk,
            "stacking_flag": self.stacking_flag,
            "flagged_chunk_count": self.flagged_chunk_count,
            "chunks": [c.to_dict() for c in self.chunk_results],
        }


# ─── Core scanning ────────────────────────────────────────────────────────────

def _action_for_risk(risk: int, third_party_hits: List[str], hidden_text_hits: List[str]) -> str:
    if hidden_text_hits:
        # Hidden text aimed at the model is close to always malicious intent —
        # legitimate content has no reason to hide instructions from readers.
        return "block"
    if risk >= 70:
        return "block"
    if risk >= 40 or third_party_hits:
        return "quarantine"   # hold for review / route to a stricter model, don't auto-inject
    if risk >= 20:
        return "redact"       # strip just the flagged span, keep the rest of the chunk
    return "allow"


def scan_document(
    text: str,
    source: str = "unknown",
    source_trust: str = DEFAULT_TRUST,
    raw_markup: Optional[str] = None,
) -> ChunkScanResult:
    """
    Scan a single retrieved chunk/document before it enters LLM context.

    text        : extracted/plain text content of the chunk.
    source      : identifier for where this came from (URL, doc id, etc.)
                  — surfaced in results so you can build a per-source
                  reputation feed over time.
    source_trust: one of "verified" | "internal" | "unverified" | "untrusted".
    raw_markup  : optional original HTML/markdown, if available, to run
                  hidden-text detection against (extracted text alone won't
                  show display:none or white-on-white tricks).
    """
    rule_result = rule_engine.analyze(text)
    third_party_hits = detect_third_party_imperatives(text)
    hidden_text_hits = detect_hidden_text_markup(raw_markup) if raw_markup else []

    trust_multiplier = TRUST_MULTIPLIERS.get(source_trust, TRUST_MULTIPLIERS[DEFAULT_TRUST])
    risk = rule_result.risk_score

    if third_party_hits:
        risk = min(100, risk + 20)
    if hidden_text_hits:
        risk = min(100, risk + 35)  # concealment from a human reader is a strong standalone signal

    risk = min(100, round(risk * trust_multiplier))

    attack_types = list(rule_result.attack_types)
    if third_party_hits:
        attack_types.append("Indirect Injection (Third-Party Directive)")
    if hidden_text_hits:
        attack_types.append("Concealed Instruction (Hidden Text)")

    action = _action_for_risk(risk, third_party_hits, hidden_text_hits)
    safe = action == "allow"

    reason_parts = []
    if rule_result.attack_types:
        reason_parts.append(f"pattern match: {', '.join(rule_result.attack_types)}")
    if third_party_hits:
        reason_parts.append(f"third-party directive: {', '.join(third_party_hits)}")
    if hidden_text_hits:
        reason_parts.append("hidden/concealed text detected in source markup")
    reason = "; ".join(reason_parts) if reason_parts else "No indirect injection signal detected"

    return ChunkScanResult(
        safe=safe,
        source=source,
        source_trust=source_trust,
        risk_score=risk,
        severity=rule_engine.severity_level(risk),
        attack_types=attack_types,
        patterns=rule_result.patterns,
        third_party_directives=third_party_hits,
        hidden_text_techniques=hidden_text_hits,
        obfuscation_detected=rule_result.obfuscation_detected,
        recommended_action=action,
        reason=reason,
    )


def scan_retrieval_set(chunks: List[Dict]) -> RetrievalSetResult:
    """
    Scan an entire retrieved set (e.g. top-k RAG results) as a batch.

    chunks: list of dicts, each with keys:
        text          (required)
        source        (optional)
        source_trust  (optional)
        raw_markup    (optional)

    Applies a stacking check across the whole set: several individually
    low-risk chunks that all hit the SAME attack category is itself a
    signal (mirrors rule_engine's within-prompt stacking bonus, applied
    across chunks instead of within one).
    """
    results = [
        scan_document(
            text=c["text"],
            source=c.get("source", "unknown"),
            source_trust=c.get("source_trust", DEFAULT_TRUST),
            raw_markup=c.get("raw_markup"),
        )
        for c in chunks
    ]

    flagged = [r for r in results if not r.safe]

    category_counts: Dict[str, int] = {}
    for r in results:
        for a in r.attack_types:
            category_counts[a] = category_counts.get(a, 0) + 1
    stacking_flag = any(count >= 2 for count in category_counts.values())

    if results:
        aggregate_risk = max(r.risk_score for r in results)
        if stacking_flag:
            aggregate_risk = min(100, aggregate_risk + 15)
    else:
        aggregate_risk = 0

    return RetrievalSetResult(
        safe=(len(flagged) == 0) and not stacking_flag,
        chunk_results=results,
        aggregate_risk=aggregate_risk,
        stacking_flag=stacking_flag,
        flagged_chunk_count=len(flagged),
    )


def redact(text: str, patterns: List[str]) -> str:
    """
    Strip flagged spans from a chunk rather than dropping it entirely —
    useful for the "redact" action, where the rest of the document is
    still useful context.
    """
    redacted = text
    for p in patterns:
        redacted = re.sub(re.escape(p), "[REDACTED]", redacted, flags=re.IGNORECASE)
    return redacted
