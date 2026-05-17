#!/usr/bin/env python3
"""
AgentShield community rules — unit test.
Loads every rule YAML, compiles the regex detector, and runs should_match /
should_not_match test cases from the rule file.

No live infrastructure needed. Runs in CI on every PR.

Usage:
    python scripts/test_rules.py                 # all rules
    python scripts/test_rules.py --category tool-abuse
    python scripts/test_rules.py --rule direct-instruction-override
    python scripts/test_rules.py --fail-fast
"""

import argparse
import re
import sys
import os
from pathlib import Path

try:
    import yaml
except ImportError:
    sys.exit("pip install pyyaml")

RULES_DIR = Path(__file__).parent.parent / "rules"

def load_rules(category=None, rule_id=None):
    rules = []
    for path in sorted(RULES_DIR.rglob("*.yaml")):
        with open(path) as f:
            try:
                data = yaml.safe_load(f)
            except yaml.YAMLError as e:
                print(f"YAML ERROR {path}: {e}")
                continue
        if data.get("schema_version") != "agentshield-rule-v0.1":
            continue
        if category and Path(path).parent.name != category:
            continue
        if rule_id and data.get("rule_id") != rule_id:
            continue
        rules.append((path, data))
    return rules

def test_rule(path, rule):
    rid = rule.get("rule_id", "unknown")
    detector = rule.get("detector", {})
    test_cases = rule.get("test_cases", {})

    if detector.get("type") != "regex":
        # Heuristic rules can't be unit-tested with regex matching.
        print(f"  SKIP  {rid}  (type: {detector.get('type', 'unknown')} — no regex to test)")
        return None, 0, 0

    pattern_str = detector.get("pattern")
    if not pattern_str:
        print(f"  ERROR {rid}  missing detector.pattern")
        return False, 0, 0

    # Convert Rust-style inline flag disabling to Python-compatible format
    # Rust: (?-i)pattern  — Python doesn't support bare (?-i); strip it for testing.
    # Production uses the Rust engine; Python testing just strips the flag.
    # Only strip (?-i), NOT (?i) — the latter is valid Python syntax.
    pattern_str = re.sub(r'^\(\?-i\)', '', pattern_str)

    try:
        pattern = re.compile(pattern_str)
    except re.error as e:
        print(f"  ERROR {rid}  invalid regex: {e}")
        return False, 0, 0

    passed = 0
    failed = 0
    failures = []

    if isinstance(test_cases, list):
        # Legacy list format: each item is {input: ..., expected: match|no_match|block|pass}
        should_match = [
            item["input"] for item in test_cases
            if isinstance(item, dict) and item.get("expected") in ("match", "block")
        ]
        should_not_match = [
            item["input"] for item in test_cases
            if isinstance(item, dict) and item.get("expected") in ("no_match", "pass")
        ]
    else:
        should_match = test_cases.get("should_match", [])
        should_not_match = test_cases.get("should_not_match", [])

    if not should_match and not should_not_match:
        print(f"  SKIP  {rid}  (no test_cases)")
        return None, 0, 0

    for sample in should_match:
        if pattern.search(str(sample)):
            passed += 1
        else:
            failed += 1
            failures.append(f"SHOULD MATCH but didn't: {repr(sample)}")

    for sample in should_not_match:
        if not pattern.search(str(sample)):
            passed += 1
        else:
            failed += 1
            failures.append(f"SHOULD NOT MATCH but did: {repr(sample)}")

    status = "PASS" if failed == 0 else "FAIL"
    print(f"  {status}  {rid}  ({passed}/{passed+failed} test cases)")
    for f in failures:
        print(f"         ↳ {f}")

    return failed == 0, passed, failed

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--category", help="Filter by category directory name")
    parser.add_argument("--rule", help="Filter by rule_id")
    parser.add_argument("--fail-fast", action="store_true")
    args = parser.parse_args()

    rules = load_rules(category=args.category, rule_id=args.rule)
    if not rules:
        print("No rules found matching filter.")
        sys.exit(1)

    total_pass = total_fail = total_skip = 0
    had_failure = False

    categories = {}
    for path, rule in rules:
        cat = Path(path).parent.name
        categories.setdefault(cat, []).append((path, rule))

    for cat, cat_rules in sorted(categories.items()):
        print(f"\n── {cat} ({len(cat_rules)} rules) ──")
        for path, rule in cat_rules:
            ok, p, f = test_rule(path, rule)
            if ok is None:
                total_skip += 1
            elif ok:
                total_pass += 1
            else:
                total_fail += 1
                had_failure = True
                if args.fail_fast:
                    print("\nFAIL FAST — stopping.")
                    sys.exit(1)

    print(f"\n{'='*50}")
    print(f"Results: {total_pass} passed  {total_fail} failed  {total_skip} skipped")
    if had_failure:
        print("OVERALL: FAIL")
        sys.exit(1)
    else:
        print("OVERALL: PASS")

if __name__ == "__main__":
    main()
