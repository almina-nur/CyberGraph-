"""Baseline varlik cikarimi ve erisim degerlendirme betigi.

Kullanim:
    python experiments/eval_baseline.py
"""

from __future__ import annotations

import json
from pathlib import Path

from cybergraph.evaluation.metrics import evaluate_set_extraction, evaluate_top_k
from cybergraph.extraction.extractor import ThreatTextExtractor

ROOT = Path(__file__).resolve().parent.parent
ATTACK_JSON = ROOT / "data/samples/enterprise-attack.json"
REPORTS_DIR = ROOT / "reports"

SAMPLE_BENCHMARK = [
    {
        "id": "case_01_actor_malware_tech",
        "text": (
            "APT29 utilized Cobalt Strike and PowerShell while communicating with "
            "hxxp://malicious-domain[.]example[.]com and 185.220.101.4."
        ),
        "expected_attack_keys": ["G0016", "S0154", "T1059.001"],
    },
    {
        "id": "case_02_discovery_tools_cve",
        "text": (
            "Adversaries leveraged BloodHound and AdFind to enumerate directory "
            "structures and exploit CVE-2023-23397."
        ),
        "expected_attack_keys": ["S0521", "S0552"],
    },
    {
        "id": "case_03_aliases_and_subtechniques",
        "text": (
            "The Dukes operated alongside Cozy Bear, dumping LSA Secrets and "
            "transferring payloads via Ingress Tool Transfer."
        ),
        "expected_attack_keys": ["G0016", "T1003.004", "T1105"],
    },
    {
        "id": "case_04_ioc_only_no_attack_entity",
        "text": (
            "Firewall logs flagged outbound connections to 203.0.113.45 and "
            "hxxps://update[.]example[.]net/check with CVE-2024-21626."
        ),
        "expected_attack_keys": [],
    },
]


def main() -> None:
    if ATTACK_JSON.exists():
        extractor = ThreatTextExtractor.from_attack_json(ATTACK_JSON)
    else:
        print("Uyari: enterprise-attack.json bulunamadi, bos sozluk ile calisiliyor.")
        extractor = ThreatTextExtractor()

    case_results = []
    precisions, recalls, f1s = [], [], []

    for item in SAMPLE_BENCHMARK:
        extracted = extractor.extract_all(item["text"])
        pred_keys = [
            m.matched_key
            for m in extracted["attack_entities"]
            if m.matched_key is not None
        ]
        metrics = evaluate_set_extraction(
            predicted_items=pred_keys,
            expected_items=item["expected_attack_keys"],
        )
        precisions.append(metrics.precision)
        recalls.append(metrics.recall)
        f1s.append(metrics.f1)

        case_results.append(
            {
                "id": item["id"],
                "predicted_keys": pred_keys,
                "expected_keys": item["expected_attack_keys"],
                "indicator_count": len(extracted["indicators"]),
                "true_positives": metrics.true_positives,
                "false_positives": metrics.false_positives,
                "false_negatives": metrics.false_negatives,
                "precision": metrics.precision,
                "recall": metrics.recall,
                "f1": metrics.f1,
            }
        )

    sample_topk = evaluate_top_k(
        ranked_keys=["S0154", "T1059.001", "S0037", "S0049", "S0050"],
        relevant_keys=["S0154", "T1059.001"],
        k=3,
    )

    summary = {
        "benchmark_cases": len(case_results),
        "mean_precision": round(sum(precisions) / len(precisions), 4),
        "mean_recall": round(sum(recalls) / len(recalls), 4),
        "mean_f1": round(sum(f1s) / len(f1s), 4),
        "sample_top3": {
            "precision_at_k": sample_topk.precision_at_k,
            "recall_at_k": sample_topk.recall_at_k,
            "f1_at_k": sample_topk.f1_at_k,
        },
        "cases": case_results,
    }

    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    out_file = REPORTS_DIR / "baseline_eval.json"
    out_file.write_text(json.dumps(summary, indent=2), encoding="utf-8")

    print(json.dumps(summary, indent=2))
    print(f"Rapor kaydedildi: {out_file}")


if __name__ == "__main__":
    main()
