from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .scanner import scan_path


RISKY_LABELS = {"malicious", "suspicious", "high_risk"}
RISKY_SEVERITIES = {"medium", "high", "critical"}


def run_evaluation(labels_path: Path) -> dict[str, Any]:
    benchmark = json.loads(labels_path.read_text(encoding="utf-8"))
    base_dir = labels_path.parent
    case_results = [_evaluate_case(base_dir, case) for case in benchmark.get("cases", [])]
    confusion = _confusion(case_results)
    metrics = _metrics(confusion)
    static_metrics = _static_metrics(case_results)
    metrics["escalation_rate"] = static_metrics["escalation_rate"]
    return {
        "schema_version": 1,
        "benchmark": benchmark.get("name", labels_path.stem),
        "benchmark_version": benchmark.get("benchmark_version"),
        "labels_path": str(labels_path),
        "case_count": len(case_results),
        "metrics": metrics,
        "confusion": confusion,
        "static_metrics": static_metrics,
        "rule_coverage": _rule_coverage(case_results),
        "cases": case_results,
    }


def _evaluate_case(base_dir: Path, case: dict[str, Any]) -> dict[str, Any]:
    target = (base_dir / str(case["path"])).resolve()
    result = scan_path(target)
    observed_rule_ids = sorted({finding.rule_id for finding in result.findings})
    expected_rule_ids = [str(rule_id) for rule_id in case.get("expected_rule_ids", [])]
    expected_risky = str(case.get("label", "")).lower() in RISKY_LABELS
    predicted_risky = any(finding.severity in RISKY_SEVERITIES for finding in result.findings)
    return {
        "id": case.get("id", target.name),
        "path": str(case["path"]),
        "label": case.get("label"),
        "attack_class": case.get("attack_class"),
        "source_paper": case.get("source_paper"),
        "expected_risky": expected_risky,
        "predicted_risky": predicted_risky,
        "max_severity": result.max_severity,
        "expected_rule_ids": expected_rule_ids,
        "observed_rule_ids": observed_rule_ids,
        "missing_expected_rule_ids": sorted(set(expected_rule_ids) - set(observed_rule_ids)),
        "finding_count": len(result.findings),
        "severity_counts": _severity_counts([finding.severity for finding in result.findings]),
    }


def _confusion(case_results: list[dict[str, Any]]) -> dict[str, int]:
    counts = {"tp": 0, "fp": 0, "tn": 0, "fn": 0}
    for case in case_results:
        expected = bool(case["expected_risky"])
        predicted = bool(case["predicted_risky"])
        if expected and predicted:
            counts["tp"] += 1
        elif not expected and predicted:
            counts["fp"] += 1
        elif not expected and not predicted:
            counts["tn"] += 1
        else:
            counts["fn"] += 1
    return counts


def _metrics(confusion: dict[str, int]) -> dict[str, float]:
    tp = confusion["tp"]
    fp = confusion["fp"]
    tn = confusion["tn"]
    fn = confusion["fn"]
    precision = _safe_div(tp, tp + fp)
    recall = _safe_div(tp, tp + fn)
    f1 = _safe_div(2 * precision * recall, precision + recall)
    f2 = _fbeta(precision, recall, beta=2)
    fpr = _safe_div(fp, fp + tn)
    total = tp + fp + tn + fn
    suspicious_rate = _safe_div(tp + fp, total)
    return {
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "f2": f2,
        "fpr": fpr,
        "false_positive_rate": fpr,
        "suspicious_rate": suspicious_rate,
        "escalation_rate": 0.0,
    }


def _static_metrics(case_results: list[dict[str, Any]]) -> dict[str, Any]:
    severity_counts = {"info": 0, "low": 0, "medium": 0, "high": 0, "critical": 0}
    finding_count = 0
    escalation_cases = 0
    for case in case_results:
        finding_count += int(case["finding_count"])
        case_counts = case["severity_counts"]
        for severity in severity_counts:
            severity_counts[severity] += int(case_counts.get(severity, 0))
        if case["max_severity"] in {"high", "critical"}:
            escalation_cases += 1
    return {
        "finding_count": finding_count,
        "severity_counts": severity_counts,
        "escalation_cases": escalation_cases,
        "escalation_rate": _safe_div(escalation_cases, len(case_results)),
    }


def _rule_coverage(case_results: list[dict[str, Any]]) -> dict[str, Any]:
    expected_cases = [
        case for case in case_results if case["expected_rule_ids"]
    ]
    covered_cases = [
        case for case in expected_cases if not case["missing_expected_rule_ids"]
    ]
    expected_rules = sorted(
        {
            rule_id
            for case in expected_cases
            for rule_id in case["expected_rule_ids"]
        }
    )
    observed_expected_rules = sorted(
        {
            rule_id
            for case in expected_cases
            for rule_id in case["expected_rule_ids"]
            if rule_id in case["observed_rule_ids"]
        }
    )
    return {
        "covered_cases": len(covered_cases),
        "expected_cases": len(expected_cases),
        "coverage": _safe_div(len(covered_cases), len(expected_cases)),
        "expected_rule_ids": expected_rules,
        "observed_expected_rule_ids": observed_expected_rules,
    }


def _severity_counts(severities: list[str]) -> dict[str, int]:
    counts = {"info": 0, "low": 0, "medium": 0, "high": 0, "critical": 0}
    for severity in severities:
        counts[severity] = counts.get(severity, 0) + 1
    return counts


def _fbeta(precision: float, recall: float, beta: float) -> float:
    beta_squared = beta * beta
    return _safe_div((1 + beta_squared) * precision * recall, (beta_squared * precision) + recall)


def _safe_div(numerator: float, denominator: float) -> float:
    if denominator == 0:
        return 0.0
    return round(numerator / denominator, 4)
