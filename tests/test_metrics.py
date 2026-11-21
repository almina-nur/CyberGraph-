import pytest

from cybergraph.evaluation.metrics import evaluate_set_extraction, evaluate_top_k


def test_evaluate_set_extraction():
    metrics = evaluate_set_extraction(
        predicted_items=["G0016", "S0154", "T9999"],
        expected_items=["G0016", "S0154", "T1059"],
    )
    assert metrics.true_positives == 2
    assert metrics.false_positives == 1
    assert metrics.false_negatives == 1
    assert metrics.precision == pytest.approx(2 / 3, abs=1e-4)
    assert metrics.recall == pytest.approx(2 / 3, abs=1e-4)
    assert metrics.f1 == pytest.approx(2 / 3, abs=1e-4)


def test_evaluate_top_k():
    res = evaluate_top_k(
        ranked_keys=["S0154", "T1059", "S0001", "T1003"],
        relevant_keys=["S0154", "T1059"],
        k=2,
    )
    assert res.precision_at_k == 1.0
    assert res.recall_at_k == 1.0
    assert res.f1_at_k == 1.0
