"""Shared character CNN, document scoring, and logit-gradient explanations."""
from dataclasses import asdict, dataclass
from pathlib import Path
import hashlib
import pickle
import time
import numpy as np
import torch
from torch import nn
from .preprocessing import MAX_LEN, PREPROCESSING_VERSION, text_windows


class AttackCNN(nn.Module):
    def __init__(self, vocab_size: int):
        super().__init__()
        self.embedding = nn.Embedding(vocab_size, 32, padding_idx=0)
        self.conv1 = nn.Conv1d(32, 64, 3, padding=1)
        self.conv2 = nn.Conv1d(64, 64, 3, padding=1)
        self.conv3 = nn.Conv1d(64, 32, 3, padding=1)
        self.pool = nn.AdaptiveMaxPool1d(1)
        self.avgpool = nn.AdaptiveAvgPool1d(1)
        self.fc1 = nn.Linear(64, 32)
        self.fc2 = nn.Linear(32, 1)
        self.dropout = nn.Dropout(0.30)

    def forward_from_embeddings(self, embeddings):
        x = embeddings.transpose(1, 2)
        x = torch.relu(self.conv1(x))
        x = torch.relu(self.conv2(x))
        x = torch.relu(self.conv3(x))
        x = torch.cat((self.pool(x).squeeze(-1), self.avgpool(x).squeeze(-1)), 1)
        return self.fc2(self.dropout(torch.relu(self.fc1(x)))).squeeze(-1)

    def forward(self, x):
        return self.forward_from_embeddings(self.embedding(x))


def encode_text(text, vocabulary):
    windows = text_windows(text)
    encoded = np.zeros((len(windows), MAX_LEN), dtype=np.int64)
    for i, (_, visible) in enumerate(windows):
        if visible:
            encoded[i, -len(visible):] = [vocabulary.get(c, 1) for c in visible]
    return torch.from_numpy(encoded), windows


def document_logits(model, windows, owners, count):
    logits = model(windows)
    return torch.full((count,), -torch.inf, device=logits.device).scatter_reduce(
        0, owners, logits, reduce="amax", include_self=True
    )


@dataclass(frozen=True)
class ExplanationSpan:
    text: str
    start: int
    end: int
    importance: float


@dataclass(frozen=True)
class DetectionResult:
    score: float
    is_attack: bool
    inference_latency_ms: float
    explanation_latency_ms: float
    inspected_text: str
    influential_spans: tuple[ExplanationSpan, ...] = ()
    window_count: int = 1

    def to_dict(self):
        return asdict(self)


class AttackDetector:
    def __init__(self, model_path: Path, vocabulary_path: Path, threshold=None):
        with vocabulary_path.open("rb") as stream:
            self.char2idx = pickle.load(stream)
        checkpoint = torch.load(model_path, map_location="cpu", weights_only=True)
        if checkpoint.get("preprocessing_version") != PREPROCESSING_VERSION:
            raise ValueError("Model preprocessing version mismatch; retrain with train.py")
        if hashlib.sha256(vocabulary_path.read_bytes()).hexdigest() != checkpoint["vocabulary_sha256"]:
            raise ValueError("Model and vocabulary artifact hashes do not match")
        self.model = AttackCNN(max(self.char2idx.values()) + 1)
        self.model.load_state_dict(checkpoint["state_dict"])
        self.model.eval()
        self.threshold = float(checkpoint["threshold"] if threshold is None else threshold)
        if not 0 < self.threshold < 1:
            raise ValueError("Threshold must lie strictly between 0 and 1")

    def encode(self, text):
        return encode_text(text, self.char2idx)

    def predict(self, text, explain=True):
        tensor, windows = self.encode(text)
        started = time.perf_counter()
        with torch.inference_mode():
            logits = self.model(tensor)
            winner = int(logits.argmax())
            score = float(torch.sigmoid(logits[winner]))
        inference_ms = (time.perf_counter() - started) * 1000
        is_attack = score > self.threshold
        spans, explanation_ms = (), 0.0
        if explain and is_attack and text:
            started = time.perf_counter()
            offset, visible = windows[winner]
            spans = self._explain(tensor[winner:winner + 1], visible, offset)
            explanation_ms = (time.perf_counter() - started) * 1000
        return DetectionResult(score, is_attack, inference_ms, explanation_ms, text, spans, len(windows))

    def saliency(self, tensor, length):
        # Differentiate the logit so sigmoid saturation cannot erase saliency.
        # autograd.grad avoids writes to shared parameter gradients.
        embeddings = self.model.embedding(tensor).detach().requires_grad_(True)
        logit = self.model.forward_from_embeddings(embeddings).sum()
        gradient, = torch.autograd.grad(logit, embeddings)
        return (gradient * embeddings).abs().sum(2)[0, -length:].detach().numpy()

    def _explain(self, tensor, visible, offset=0):
        values = self.saliency(tensor, len(visible))
        maximum = float(values.max(initial=0))
        if maximum <= 0:
            return ()
        values /= maximum
        selected = values >= max(float(np.quantile(values, .75)), .20)
        candidates, start = [], None
        for index, active in enumerate(np.append(selected, False)):
            if active and start is None:
                start = index
            elif not active and start is not None:
                candidates.append((float(values[start:index].mean()), max(0, start - 10), min(len(visible), index + 10)))
                start = None
        spans = []
        for importance, start, end in sorted(candidates, reverse=True):
            if any(start >= s.start - offset and end <= s.end - offset for s in spans):
                continue
            spans.append(ExplanationSpan(visible[start:end], offset + start, offset + end, round(importance, 4)))
            if len(spans) == 3:
                break
        return tuple(spans)
