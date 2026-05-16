#!/usr/bin/env python3
"""
AgentShield community-rules validator.

Usage:
    python scripts/validate.py --all
    python scripts/validate.py rules/experimental/adversarial-suffix.yaml
    python scripts/validate.py profiles/hipaa.yaml

Exit codes:
    0 — all files passed
    1 — one or more files failed validation
"""

import argparse
import json
import sys
from pathlib import Path

import yaml
import jsonschema

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
REPO_ROOT = Path(__file__).resolve().parent.parent
RULE_SCHEMA_PATH = REPO_ROOT / "schema" / "rule.schema.json"

# Directories to scan when --all is given
SCAN_DIRS = [
    REPO_ROOT / "rules",
    REPO_ROOT / "profiles",
]

# Minimum required keys for a compliance profile (no JSON Schema for these yet)
PROFILE_REQUIRED_KEYS = {
    "schema_version",
    "compliance_profile",
    "description",
    "substrate_rules",
    "atcs_authority_ceiling",
}

PROFILE_SCHEMA_VERSION = "agentos-rule-pack-v0.1"
RULE_SCHEMA_VERSION = "agentshield-rule-v0.1"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def load_schema(path: Path) -> dict:
    with path.open() as fh:
        return json.load(fh)


def load_yaml(path: Path) -> object:
    with path.open() as fh:
        return yaml.safe_load(fh)


def validate_rule(data: dict, schema: dict, path: Path) -> list[str]:
    """Validate a rule YAML against rule.schema.json. Return list of errors."""
    errors: list[str] = []
    validator = jsonschema.Draft7Validator(schema)
    for error in sorted(validator.iter_errors(data), key=lambda e: list(e.path)):
        location = " -> ".join(str(p) for p in error.path) if error.path else "<root>"
        errors.append(f"  [{location}] {error.message}")
    return errors


def validate_profile(data: dict, path: Path) -> list[str]:
    """Validate a compliance profile YAML with basic structural checks."""
    errors: list[str] = []
    if not isinstance(data, dict):
        return ["  Document is not a YAML mapping."]

    # schema_version check
    sv = data.get("schema_version")
    if sv != PROFILE_SCHEMA_VERSION:
        errors.append(
            f"  [schema_version] Expected '{PROFILE_SCHEMA_VERSION}', got '{sv}'."
        )

    # required keys
    for key in sorted(PROFILE_REQUIRED_KEYS):
        if key not in data:
            errors.append(f"  [{key}] Required field is missing.")

    # substrate_rules must be a list
    sr = data.get("substrate_rules")
    if sr is not None and not isinstance(sr, list):
        errors.append("  [substrate_rules] Must be a list.")

    # atcs_authority_ceiling allowed values
    ceiling = data.get("atcs_authority_ceiling")
    allowed_ceilings = {"READ_ONLY", "WRITE_STANDARD", "WRITE_ELEVATED", "ADMIN"}
    if ceiling is not None and ceiling not in allowed_ceilings:
        errors.append(
            f"  [atcs_authority_ceiling] '{ceiling}' is not one of {sorted(allowed_ceilings)}."
        )

    return errors


def is_profile(data: object, path: Path) -> bool:
    """Return True if the document looks like a compliance profile."""
    if not isinstance(data, dict):
        return False
    sv = data.get("schema_version", "")
    return sv == PROFILE_SCHEMA_VERSION or "compliance_profile" in data


# ---------------------------------------------------------------------------
# Core validation logic
# ---------------------------------------------------------------------------

def validate_file(path: Path, rule_schema: dict) -> bool:
    """
    Validate a single YAML file.

    Returns True on success, False on failure.
    Prints a pass/fail line (and errors) to stdout.
    """
    try:
        data = load_yaml(path)
    except yaml.YAMLError as exc:
        print(f"FAIL  {path.relative_to(REPO_ROOT)}")
        print(f"  YAML parse error: {exc}")
        return False
    except OSError as exc:
        print(f"FAIL  {path.relative_to(REPO_ROOT)}")
        print(f"  Cannot read file: {exc}")
        return False

    if data is None:
        print(f"FAIL  {path.relative_to(REPO_ROOT)}")
        print("  File is empty or contains only comments.")
        return False

    if is_profile(data, path):
        errors = validate_profile(data, path)
    else:
        errors = validate_rule(data, rule_schema, path)

    rel = path.relative_to(REPO_ROOT)
    if errors:
        print(f"FAIL  {rel}")
        for err in errors:
            print(err)
        return False
    else:
        print(f"PASS  {rel}")
        return True


def collect_yaml_files(directories: list[Path]) -> list[Path]:
    files: list[Path] = []
    for d in directories:
        if not d.exists():
            continue
        for p in sorted(d.rglob("*.yaml")):
            files.append(p)
        for p in sorted(d.rglob("*.yml")):
            files.append(p)
    # Deduplicate while preserving order
    seen: set[Path] = set()
    result: list[Path] = []
    for f in files:
        if f not in seen:
            seen.add(f)
            result.append(f)
    return result


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Validate AgentShield rule and profile YAML files."
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--all",
        action="store_true",
        help="Validate every YAML file in rules/ and profiles/.",
    )
    group.add_argument(
        "file",
        nargs="?",
        type=Path,
        help="Path to a single YAML file to validate.",
    )
    args = parser.parse_args()

    # Load rule schema once
    if not RULE_SCHEMA_PATH.exists():
        print(f"ERROR: Rule schema not found at {RULE_SCHEMA_PATH}", file=sys.stderr)
        return 1
    rule_schema = load_schema(RULE_SCHEMA_PATH)

    # Collect files
    if args.all:
        files = collect_yaml_files(SCAN_DIRS)
        if not files:
            print("No YAML files found in rules/ or profiles/.", file=sys.stderr)
            return 1
    else:
        target = args.file.resolve() if args.file else None
        if target is None or not target.exists():
            print(f"ERROR: File not found: {args.file}", file=sys.stderr)
            return 1
        files = [target]

    # Validate
    results = [validate_file(f, rule_schema) for f in files]

    total = len(results)
    passed = sum(results)
    failed = total - passed

    print()
    print(f"Results: {passed}/{total} passed, {failed} failed.")

    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
