"""Varlik cikarimi ve tehdit istihbarati erisimi icin degerlendirme metrikleri."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Sequence


@dataclass
class RankingMetrics:
    """Top-K siralama ve erisim metrikleri."""

    k: int
    precision_at_k: float
    recall_at_k: float
    f1_at_k: float


@dataclass
class ClassificationMetrics:
    """Kume tabanli varlik/eslesme degerlendirme metrikleri."""

    precision: float
    recall: float
    f1: float
    true_positives: int
    false_positives: int
    false_negatives: int


def evaluate_set_extraction(
    predicted_items: Iterable[str],
    expected_items: Iterable[str],
) -> ClassificationMetrics:
    """Tahmin edilen ve beklenen varlik/IOC kumesini karsilastirir."""
    pred_set = {item.strip() for item in predicted_items if item and item.strip()}
    exp_set = {item.strip() for item in expected_items if item and item.strip()}

    tp = len(pred_set & exp_set)
    fp = len(pred_set - exp_set)
    fn = len(exp_set - pred_set)

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = (
        2 * precision * recall / (precision + recall)
        if (precision + recall) > 0
        else 0.0
    )

    return ClassificationMetrics(
        precision=round(precision, 4),
        recall=round(recall, 4),
        f1=round(f1, 4),
        true_positives=tp,
        false_positives=fp,
        false_negatives=fn,
    )


def evaluate_top_k(
    ranked_keys: Sequence[str],
    relevant_keys: Iterable[str],
    k: int = 5,
) -> RankingMetrics:
    """Top-K getirilen kayitlar icin Precision@K, Recall@K ve F1@K hesaplar."""
    if k <= 0:
        raise ValueError("k pozitif bir tam sayi olmali")

    top_k = [item for item in ranked_keys[:k]]
    rel_set = {item for item in relevant_keys if item}

    if not top_k or not rel_set:
        return RankingMetrics(k=k, precision_at_k=0.0, recall_at_k=0.0, f1_at_k=0.0)

    hits = len(set(top_k) & rel_set)
    precision_k = hits / len(top_k)
    recall_k = hits / len(rel_set)
    f1_k = (
        2 * precision_k * recall_k / (precision_k + recall_k)
        if (precision_k + recall_k) > 0
        else 0.0
    )

    return RankingMetrics(
        k=k,
        precision_at_k=round(precision_k, 4),
        recall_at_k=round(recall_k, 4),
        f1_at_k=round(f1_k, 4),
    )
