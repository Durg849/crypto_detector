"""
ml_detector.py
────────────────────────────────────────────────────────────────────────────
Layer 2 of Injecto's detection pipeline: a lightweight statistical model
that catches paraphrased / novel injection attempts the rule engine's exact
keyword matches would miss (e.g. "kindly disregard prior guidance").

Primary path:  TF-IDF + Logistic Regression, trained on dataset.csv at
                process startup and cached in memory.
Fallback path: if scikit-learn isn't installed, or training data is too
                small/missing, falls back to a hand-written heuristic
                scorer so the layer never hard-crashes the pipeline.

Public API:
    predict(prompt: str) -> MLResult
"""

import os
import re
from dataclasses import dataclass

DATASET_PATH = os.path.join(os.path.dirname(__file__), "dataset.csv")

_INJECTION_CUES = [
    "ignore", "disregard", "bypass", "override", "jailbreak", "forget",
    "pretend", "act as", "developer mode", "system prompt", "reveal",
    "unlock", "no restrictions", "without limitations", "root access",
    "admin mode", "dan", "persona", "disable", "unfiltered",
]


@dataclass
class MLResult:
    safe: bool
    confidence: float          # probability the prompt IS an injection, 0-1
    risk_score: int            # 0-100, mirrors confidence for pipeline math
    method: str                # "trained_model" or "heuristic_fallback"


# ─── Attempt to build a trained model (once, at import time) ───────────────

_model = None
_vectorizer = None
_model_error = None
_prompts = []

try:
    import csv
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import LogisticRegression

    def _load_dataset():
        prompts, labels = [], []
        if not os.path.exists(DATASET_PATH):
            return prompts, labels
        with open(DATASET_PATH, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                p = (row.get("prompt") or "").strip()
                lbl = (row.get("label") or "").strip().lower()
                if p and lbl in ("safe", "injection"):
                    prompts.append(p)
                    labels.append(1 if lbl == "injection" else 0)
        return prompts, labels

    _prompts, _labels = _load_dataset()

    # Need at least a couple examples of each class to train anything sane.
    if len(set(_labels)) == 2 and len(_prompts) >= 6:
        _vectorizer = TfidfVectorizer(ngram_range=(1, 2), min_df=1)
        X = _vectorizer.fit_transform(_prompts)
        _model = LogisticRegression(max_iter=1000, class_weight="balanced")
        _model.fit(X, _labels)
    else:
        _model_error = "insufficient labeled data in dataset.csv to train"

except ImportError:
    _model_error = "scikit-learn not installed"
except Exception as e:  # never let a bad dataset crash the app on import
    _model_error = f"training failed: {e}"


# ─── Heuristic fallback ─────────────────────────────────────────────────────

def _heuristic_score(prompt: str) -> float:
    """
    Cheap, dependency-free scorer used when the trained model isn't
    available. Combines cue-word density with a couple of structural
    signals (imperative phrasing, sudden role/persona language).
    """
    lowered = prompt.lower()
    words = re.findall(r"[a-z']+", lowered)
    if not words:
        return 0.0

    hits = sum(1 for cue in _INJECTION_CUES if cue in lowered)
    density = hits / max(len(words), 1)

    imperative_start = bool(re.match(r"^\s*(ignore|disregard|forget|act|pretend|reveal|bypass)\b", lowered))
    role_language = bool(re.search(r"\byou are now\b|\bas an? \w+ with no\b|\bwithout (any )?restrictions?\b", lowered))

    score = min(1.0, density * 3 + (0.25 if imperative_start else 0) + (0.25 if role_language else 0))
    return score


# ─── Public API ──────────────────────────────────────────────────────────────

def predict(prompt: str) -> MLResult:
    if _model is not None and _vectorizer is not None:
        X = _vectorizer.transform([prompt])
        proba = _model.predict_proba(X)[0]
        # class order matches training labels; index 1 == "injection"
        classes = list(_model.classes_)
        confidence = float(proba[classes.index(1)]) if 1 in classes else 0.0
        return MLResult(
            safe=confidence < 0.5,
            confidence=round(confidence, 4),
            risk_score=round(confidence * 100),
            method="trained_model",
        )

    confidence = _heuristic_score(prompt)
    return MLResult(
        safe=confidence < 0.5,
        confidence=round(confidence, 4),
        risk_score=round(confidence * 100),
        method="heuristic_fallback",
    )


def status() -> dict:
    """Small helper so /api or /admin routes can report which path is live."""
    return {
        "trained_model_active": _model is not None,
        "fallback_reason": _model_error,
        "training_examples": len(_prompts),
    }
