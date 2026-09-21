"""Versioned candidate loading without a runtime scikit-learn dependency."""
from collections import Counter
import hashlib
import json
import math
from pathlib import Path
import re
import time
from .detector import AttackDetector, DetectionResult
from .representation import REPRESENTATION_VERSION


class LinearDetector:
    explanation_method = "character TF-IDF linear score; span attribution unavailable"

    def __init__(self, path, threshold=None, preprocessing_version=REPRESENTATION_VERSION):
        artifact = json.loads(Path(path).read_text(encoding="utf-8"))
        if artifact["preprocessing_version"] != preprocessing_version:
            raise ValueError("Representation version mismatch")
        self.threshold = artifact["threshold"] if threshold is None else float(threshold)
        if not 0 <= self.threshold <= 1:
            raise ValueError("Invalid threshold")
        self.vocabulary, self.idf = artifact["vocabulary"], artifact["idf"]
        self.coefficients, self.intercept = artifact["coefficients"], artifact["intercept"]
        self.ngram_range = artifact["ngram_range"]

    def predict(self, text, explain=True):
        started = time.perf_counter()
        # Matches sklearn's char analyzer, raw counts, IDF and L2 normalization.
        normalized = re.sub(r"\s\s+", " ", text)
        counts = Counter()
        for size in range(self.ngram_range[0], self.ngram_range[1] + 1):
            for position in range(len(normalized) - size + 1):
                index = self.vocabulary.get(normalized[position:position + size])
                if index is not None:
                    counts[index] += 1
        weighted = {index: count * self.idf[index] for index, count in counts.items()}
        norm = math.sqrt(sum(value * value for value in weighted.values()))
        logit = self.intercept
        if norm:
            logit += sum(self.coefficients[index] * value / norm for index, value in weighted.items())
        score = 1 / (1 + math.exp(-max(-700, min(700, logit))))
        return DetectionResult(score, score > self.threshold, (time.perf_counter()-started)*1000,
                               0.0, text, ())


class ComponentCNNDetector(AttackDetector):
    def encode(self, text):
        import torch
        from .detector import encode_text
        from .payload_representation import SEPARATOR
        tensors, windows, offset = [], [], 0
        for part in text.split(SEPARATOR):
            encoded, local_windows = encode_text(part, self.char2idx)
            tensors.append(encoded)
            windows.extend((offset + position, value) for position, value in local_windows)
            offset += len(part) + len(SEPARATOR)
        return torch.cat(tensors), windows


def load_candidate(directory, threshold=None, expected_version=None):
    directory = Path(directory)
    selected = json.loads((directory / "selection.json").read_text(encoding="utf-8"))
    from .payload_representation import REPRESENTATION_VERSION as COMPONENT_VERSION
    version = selected.get("preprocessing_version", REPRESENTATION_VERSION)
    if version not in (REPRESENTATION_VERSION, COMPONENT_VERSION) or expected_version is not None and version != expected_version:
        raise ValueError("Candidate and runtime representation versions differ")
    name, kind = selected["selected"], selected["kind"]
    if not re.fullmatch(r"[a-zA-Z0-9_.-]+", name):
        raise ValueError("Invalid artifact name")
    path = directory / (name + (".pt" if kind == "cnn" else ".json"))
    for artifact in ([path, directory / "vocabulary.pkl"] if kind == "cnn" else [path]):
        if hashlib.sha256(artifact.read_bytes()).hexdigest() != selected["artifact_hashes"][artifact.name]:
            raise ValueError("Candidate artifact hash mismatch")
    if kind == "cnn":
        detector = ComponentCNNDetector if version == COMPONENT_VERSION else AttackDetector
        return detector(path, directory / "vocabulary.pkl", threshold=threshold,
                        preprocessing_version=version)
    if kind == "linear":
        return LinearDetector(path, threshold, preprocessing_version=version)
    raise ValueError("Unknown candidate kind")
