from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .config import load_scan_config, resolve_scan_options
from .evaluation import run_evaluation
from .jury import FakeJuryProvider, jury_schema, run_fake_jury_for_path
from .manifest import suggest_manifest
from .reporters import render_json, render_sarif, render_text
from .risk_graph import build_risk_graph
from .scanner import scan_path
from .semantic import layer2_schema
from .semantic_review import FakeSemanticProvider, run_semantic_review
from .telemetry import telemetry_schema
from .host_policy import host_profile_policy_schema
from .trust import trust_profile_schema


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="skillshield", description="Scan Agent Skill packages.")
    subparsers = parser.add_subparsers(dest="command", required=True)
    scan = subparsers.add_parser("scan", help="Scan a skill folder or tree.")
    scan.add_argument("path", type=Path)
    scan.add_argument("--format", choices=("text", "json", "sarif"), default="text")
    scan.add_argument("--fail-on", choices=("low", "medium", "high", "critical"))
    scan.add_argument(
        "--semantic-plan",
        action="store_true",
        default=None,
        help="Add provider-free Layer 2 review routing findings.",
    )
    scan.add_argument(
        "--metadata-audit",
        action="store_true",
        default=None,
        help="Add registry/package metadata audit findings.",
    )
    scan.add_argument("--config", type=Path, help="Optional JSON/TOML scan config.")
    manifest = subparsers.add_parser("manifest", help="Work with permission manifests.")
    manifest_subparsers = manifest.add_subparsers(dest="manifest_command", required=True)
    suggest = manifest_subparsers.add_parser("suggest", help="Suggest permissions from scan evidence.")
    suggest.add_argument("path", type=Path)
    suggest.add_argument("--format", choices=("json", "text"), default="json")
    semantic = subparsers.add_parser("semantic", help="Inspect Layer 2 semantic review contracts.")
    semantic_subparsers = semantic.add_subparsers(dest="semantic_command", required=True)
    semantic_subparsers.add_parser("schema", help="Print provider-neutral Layer 2 JSON schema.")
    review = semantic_subparsers.add_parser("review", help="Run an explicit Layer 2 semantic review provider.")
    review.add_argument("path", type=Path)
    review.add_argument("--provider", choices=("fake",), default="fake")
    jury = subparsers.add_parser("jury", help="Inspect or run Layer 3 jury protocol contracts.")
    jury_subparsers = jury.add_subparsers(dest="jury_command", required=True)
    jury_subparsers.add_parser("schema", help="Print provider-neutral Layer 3 jury schema.")
    jury_review = jury_subparsers.add_parser("review", help="Run a local fake Layer 3 jury.")
    jury_review.add_argument("path", type=Path)
    jury_review.add_argument("--provider", choices=("fake",), default="fake")
    graph = subparsers.add_parser("graph", help="Build a cross-skill risk graph.")
    graph.add_argument("path", type=Path)
    eval_parser = subparsers.add_parser("eval", help="Evaluate scanner results against labeled fixtures.")
    eval_parser.add_argument("labels", type=Path)
    telemetry = subparsers.add_parser("telemetry", help="Inspect local usage/adherence telemetry contracts.")
    telemetry_subparsers = telemetry.add_subparsers(dest="telemetry_command", required=True)
    telemetry_subparsers.add_parser("schema", help="Print local usage/adherence event schema.")
    trust = subparsers.add_parser("trust", help="Inspect trust tier admission policy profiles.")
    trust_subparsers = trust.add_subparsers(dest="trust_command", required=True)
    trust_subparsers.add_parser("profiles", help="Print built-in trust tier profiles.")
    trust_subparsers.add_parser("host-profiles", help="Print built-in host profile scan policies.")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "scan":
        scan_config = load_scan_config(args.config)
        try:
            options = resolve_scan_options(
                scan_config,
                cli_fail_on=args.fail_on,
                cli_semantic_plan=args.semantic_plan,
                cli_metadata_audit=args.metadata_audit,
            )
        except ValueError as error:
            parser.error(str(error))
        result = scan_path(
            args.path,
            include_semantic_review=options.semantic_plan,
            include_metadata_audit=options.metadata_audit,
            suppression_config=args.config,
            enabled_rules=set(scan_config.enabled_rules) if scan_config.enabled_rules is not None else None,
            host_profile=options.host_profile,
        )
        if args.format == "json":
            print(render_json(result))
        elif args.format == "sarif":
            print(render_sarif(result))
        else:
            print(render_text(result))
        return 1 if _should_fail(result.max_severity, options.fail_on) else 0
    if args.command == "manifest" and args.manifest_command == "suggest":
        result = scan_path(args.path)
        suggestion = suggest_manifest(result)
        if args.format == "text":
            print(_render_manifest_text(suggestion))
        else:
            print(json.dumps(suggestion, indent=2, ensure_ascii=False))
        return 0
    if args.command == "semantic" and args.semantic_command == "schema":
        print(json.dumps(layer2_schema(), indent=2, ensure_ascii=False))
        return 0
    if args.command == "semantic" and args.semantic_command == "review":
        provider = FakeSemanticProvider()
        print(json.dumps(run_semantic_review(args.path, provider), indent=2, ensure_ascii=False))
        return 0
    if args.command == "jury" and args.jury_command == "schema":
        print(json.dumps(jury_schema(), indent=2, ensure_ascii=False))
        return 0
    if args.command == "jury" and args.jury_command == "review":
        provider = FakeJuryProvider()
        if provider.name != args.provider:
            parser.error(f"unsupported jury provider: {args.provider}")
        print(json.dumps(run_fake_jury_for_path(args.path), indent=2, ensure_ascii=False))
        return 0
    if args.command == "graph":
        print(json.dumps(build_risk_graph(args.path), indent=2, ensure_ascii=False))
        return 0
    if args.command == "eval":
        print(json.dumps(run_evaluation(args.labels), indent=2, ensure_ascii=False))
        return 0
    if args.command == "telemetry" and args.telemetry_command == "schema":
        print(json.dumps(telemetry_schema(), indent=2, ensure_ascii=False))
        return 0
    if args.command == "trust" and args.trust_command == "profiles":
        print(json.dumps(trust_profile_schema(), indent=2, ensure_ascii=False))
        return 0
    if args.command == "trust" and args.trust_command == "host-profiles":
        print(json.dumps(host_profile_policy_schema(), indent=2, ensure_ascii=False))
        return 0
    parser.error("unknown command")
    return 2


def _should_fail(max_severity: str, threshold: str) -> bool:
    order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    return order[max_severity] >= order[threshold]


def _render_manifest_text(suggestion: dict) -> str:
    lines = [f"Suggested permissions for {suggestion['root']}:"]
    permissions = suggestion.get("permissions", [])
    if not permissions:
        lines.append("No permissions inferred.")
        return "\n".join(lines)
    for permission in permissions:
        lines.append(
            f"- {permission['capability']} ({permission['effect']}, {permission['protected_object']})"
        )
        for evidence in permission["evidence"]:
            location = evidence["path"]
            if evidence.get("line"):
                location += f":{evidence['line']}"
            lines.append(f"  evidence: {evidence['rule_id']} at {location}")
    return "\n".join(lines)


if __name__ == "__main__":
    sys.exit(main())
