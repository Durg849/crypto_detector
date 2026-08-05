"""
obfuscation_detector.py
────────────────────────────────────────────────────────────────────────────
Pre-processing layer that sits in front of rule_engine's pattern matching.

Purpose: attackers rarely type "ignore previous instructions" verbatim once
a filter is known to block it. Instead they obfuscate the payload so it
still reads correctly to an LLM but slips past naive keyword matching:

  • Homoglyphs / Unicode confusables   ("іgnore" using Cyrillic і)
  • Zero-width / invisible characters  ("ign\u200bore prev\u200dious")
  • Full-width / mathematical Unicode  ("ｉｇｎｏｒｅ", "𝐢𝐠𝐧𝐨𝐫𝐞")
  • Letter-spacing / separator smuggling ("i-g-n-o-r-e", "i.g.n.o.r.e")
  • Leetspeak substitution              ("1gn0r3 pr3v10u5")
  • Encoded payloads                    (base64 / hex / rot13 blobs)

None of these change what a human or an LLM reads — they only defeat exact
string matching. This module normalizes text back to a canonical ASCII
form so downstream layers (rule_engine, ml_detector) can match against it,
and reports *which* obfuscation techniques were used so that's surfaced
to the caller as its own signal (heavy obfuscation is suspicious even
before you know what the deobfuscated payload says).

Public API:
    deobfuscate(text: str) -> DeobfuscationResult
"""

import base64
import binascii
import re
import unicodedata
from dataclasses import dataclass, field
from typing import List


@dataclass
class DeobfuscationResult:
    normalized_text: str                     # best-effort canonical form
    techniques: List[str] = field(default_factory=list)
    decoded_payloads: List[str] = field(default_factory=list)  # any decoded blobs found

    @property
    def was_obfuscated(self) -> bool:
        return len(self.techniques) > 0


# ─── 1. Zero-width / invisible character stripping ─────────────────────────
# These render as nothing but sit between letters to break up blocked
# keywords, e.g. "ig\u200bnore" still reads "ignore" to an LLM.

_ZERO_WIDTH_CHARS = (
    "\u200b"  # zero width space
    "\u200c"  # zero width non-joiner
    "\u200d"  # zero width joiner
    "\u200e"  # left-to-right mark
    "\u200f"  # right-to-left mark
    "\u2060"  # word joiner
    "\u2061"  "\u2062"  "\u2063"  "\u2064"  # invisible math operators
    "\ufeff"  # BOM / zero width no-break space
    "\u00ad"  # soft hyphen
)
_ZERO_WIDTH_RE = re.compile("[" + _ZERO_WIDTH_CHARS + "]")

# Combining marks used to "Zalgo" text and break up matches, e.g. i̶g̶n̶o̶r̶e̶
_COMBINING_MARK_RE = re.compile(r"[\u0300-\u036f\u1ab0-\u1aff\u1dc0-\u1dff\u20d0-\u20ff]")


def _strip_invisible(text: str) -> str:
    text = _ZERO_WIDTH_RE.sub("", text)
    text = _COMBINING_MARK_RE.sub("", text)
    return text


# ─── 2. Homoglyph / confusable normalization ────────────────────────────────
# Common lookalike characters from Cyrillic, Greek, and other scripts that
# render visually identical (or near-identical) to Latin letters.

_CONFUSABLES = {
    # Cyrillic → Latin
    "а": "a", "А": "A", "е": "e", "Е": "E", "о": "o", "О": "O",
    "р": "p", "Р": "P", "с": "c", "С": "C", "х": "x", "Х": "X",
    "у": "y", "У": "Y", "і": "i", "І": "I", "ѕ": "s", "Ѕ": "S",
    "к": "k", "К": "K", "м": "m", "М": "M", "н": "H", "т": "t", "Т": "T",
    "в": "b", "В": "B", "г": "r", "п": "n", "ц": "u", "з": "3", "б": "6",
    # Greek → Latin
    "α": "a", "Α": "A", "β": "b", "Β": "B", "ο": "o", "Ο": "O",
    "ρ": "p", "Ρ": "P", "υ": "u", "Υ": "Y", "τ": "t", "Τ": "T",
    "ι": "i", "Ι": "I", "κ": "k", "Κ": "K", "ν": "v", "Ν": "N",
    "η": "n", "χ": "x", "Χ": "X",
    # Miscellaneous lookalikes
    "ⅰ": "i", "ⅼ": "l", "ℓ": "l", "ѡ": "w", "ó": "o", "í": "i", "á": "a",
}
_CONFUSABLE_RE = re.compile("|".join(re.escape(k) for k in _CONFUSABLES))


def _normalize_confusables(text: str) -> str:
    # NFKC first: collapses full-width forms (ｉｇｎｏｒｅ), mathematical
    # alphanumeric symbols (𝐢𝐠𝐧𝐨𝐫𝐞, 𝕚𝕘𝕟𝕠𝕣𝕖), ligatures, and other
    # compatibility-equivalent Unicode into plain ASCII where possible.
    text = unicodedata.normalize("NFKC", text)
    text = _CONFUSABLE_RE.sub(lambda m: _CONFUSABLES[m.group(0)], text)
    return text


# ─── 3. Letter-spacing / separator smuggling ────────────────────────────────
# "i-g-n-o-r-e p-r-e-v-i-o-u-s" or "i.g.n.o.r.e" or "i n s t r u c t i o n s"
# Detect runs of single letters joined by a consistent separator and
# collapse them back into words.

_SPACED_LETTERS_RE = re.compile(
    r"\b(?:[a-zA-Z][ \-\._\*/\\]){3,}[a-zA-Z]\b"
)


def _collapse_spaced_letters(text: str) -> (str, bool):
    found = False

    def _collapse(match: "re.Match") -> str:
        nonlocal found
        found = True
        word = re.sub(r"[ \-\._\*/\\]", "", match.group(0))
        return word

    new_text = _SPACED_LETTERS_RE.sub(_collapse, text)
    return new_text, found


# ─── 4. Leetspeak normalization ─────────────────────────────────────────────

_LEET_MAP = str.maketrans({
    "0": "o", "1": "i", "3": "e", "4": "a", "5": "s",
    "7": "t", "@": "a", "$": "s", "!": "i", "+": "t",
})

# Only worth flagging as "leetspeak" if it actually maps onto one of our
# known suspicious words once normalized — otherwise every product SKU or
# password example would trip this.
_LEET_TRIGGER_RE = re.compile(r"[0-9@$!+]")


def _leet_normalize(text: str) -> (str, bool):
    if not _LEET_TRIGGER_RE.search(text):
        return text, False
    candidate = text.translate(_LEET_MAP)
    return candidate, candidate.lower() != text.lower()


# ─── 5. Encoded payload detection (base64 / hex / rot13) ───────────────────
# Attackers often ask the model to decode-and-follow an encoded instruction,
# or bury the payload itself as an encoded blob so it never appears in
# plaintext. We opportunistically try to decode chunky base64/hex tokens
# found in the prompt and feed the decoded text back into the pipeline.

_BASE64_TOKEN_RE = re.compile(r"\b[A-Za-z0-9+/]{16,}={0,2}\b")
_HEX_TOKEN_RE = re.compile(r"\b(?:[0-9a-fA-F]{2}){8,}\b")
_ROT13_HINT_RE = re.compile(r"\brot13\b", re.IGNORECASE)


def _try_decode_base64(token: str) -> str:
    try:
        decoded = base64.b64decode(token, validate=True)
        text = decoded.decode("utf-8")
        # Only count it as a "decode" if it produced plausible readable text.
        if re.fullmatch(r"[\x09\x0a\x0d\x20-\x7e]+", text) and len(text) >= 6:
            return text
    except (binascii.Error, ValueError, UnicodeDecodeError):
        pass
    return ""


def _try_decode_hex(token: str) -> str:
    try:
        decoded = bytes.fromhex(token).decode("utf-8")
        if re.fullmatch(r"[\x09\x0a\x0d\x20-\x7e]+", decoded) and len(decoded) >= 6:
            return decoded
    except (ValueError, UnicodeDecodeError):
        pass
    return ""


def _rot13(text: str) -> str:
    return text.translate(str.maketrans(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
        "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm",
    ))


def _find_encoded_payloads(text: str) -> (List[str], List[str]):
    """Returns (techniques_found, decoded_texts)."""
    techniques = []
    decoded_texts = []

    for token in _BASE64_TOKEN_RE.findall(text):
        decoded = _try_decode_base64(token)
        if decoded:
            techniques.append("base64_encoded_payload")
            decoded_texts.append(decoded)

    for token in _HEX_TOKEN_RE.findall(text):
        decoded = _try_decode_hex(token)
        if decoded:
            techniques.append("hex_encoded_payload")
            decoded_texts.append(decoded)

    if _ROT13_HINT_RE.search(text):
        techniques.append("rot13_requested")
        decoded_texts.append(_rot13(text))

    return techniques, decoded_texts


# ─── Public entrypoint ───────────────────────────────────────────────────────

def _mask_encoded_tokens(text: str) -> str:
    """Blank out base64/hex-looking tokens before running the leetspeak /
    letter-spacing heuristics over the rest of the text. Otherwise digits
    that are just part of an encoded blob (base64 alphabet includes
    0-9) get misread as leetspeak substitution and inflate the risk
    score for something as ordinary as a pasted token or hash."""
    text = _BASE64_TOKEN_RE.sub(" ", text)
    text = _HEX_TOKEN_RE.sub(" ", text)
    return text


def deobfuscate(text: str) -> DeobfuscationResult:
    if not text:
        return DeobfuscationResult(normalized_text=text)

    techniques: List[str] = []
    decoded_payloads: List[str] = []

    # Encoded-payload extraction runs against the original text (needs the
    # intact tokens), separately from the plain-text obfuscation checks
    # below (which should ignore those tokens so their digits don't get
    # misread as leetspeak).
    enc_techniques, enc_decoded = _find_encoded_payloads(text)
    techniques.extend(enc_techniques)
    decoded_payloads.extend(enc_decoded)

    working = _mask_encoded_tokens(text)

    pre_strip = working
    working = _strip_invisible(working)
    if working != pre_strip:
        techniques.append("zero_width_or_invisible_chars")

    pre_confusable = working
    working = _normalize_confusables(working)
    if working != pre_confusable:
        techniques.append("homoglyph_confusables")

    working, spaced = _collapse_spaced_letters(working)
    if spaced:
        techniques.append("letter_spacing_evasion")

    working, leet = _leet_normalize(working)
    if leet:
        techniques.append("leetspeak_substitution")

    return DeobfuscationResult(
        normalized_text=working,
        techniques=techniques,
        decoded_payloads=decoded_payloads,
    )
