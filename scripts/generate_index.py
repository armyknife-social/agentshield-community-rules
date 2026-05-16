#!/usr/bin/env python3
"""
AgentShield rule index generator.

Walks the rules/ directory, extracts key metadata from each YAML rule file,
and writes a sorted index.yaml at the repo root.

Fields extracted per rule:
    rule_id, name, severity, category, content_types, owasp_llm (optional)

Rules are sorted first by category, then by rule_id.

Usage:
    python scripts/generate_index.py
"""

import sys
from pathlib import Path

import yaml

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
REPO_ROOT = Path(__file__).resolve().parent.parent
RULES_DIR = REPO_ROOT / "rules"
OUTPUT_PATH = REPO_ROOT / "index.yaml"

RULE_SCHEMA_VERSION = "agentshield-rule-v0.1"

# Fields to extract (owasp_llm is optional and may be absent)
REQUIRED_FIELDS = ["rule_id", "name", "severity", "category", "content_types"]
OPTIONAL_FIELDS = ["owasp_llm"]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def load_yaml(path: Path) -> object:
    with path.open() as fh:
        return yaml.safe_load(fh)


def is_rule_file(data: object) -> bool:
    """Return True if the document is an agentshield rule (not a profile)."""
    if not isinstance(data, dict):
        return False
    return data.get("schema_version") == RULE_SCHEMA_VERSION


def extract_entry(data: dict, path: Path) -> dict | None:
    """
    Extract index fields from a rule document.

    Returns None and prints a warning if required fields are missing.
    """
    entry: dict = {}
    missing: list[str] = []

    for field in REQUIRED_FIELDS:
        value = data.get(field)
        if value is None:
            missing.append(field)
        else:
            entry[field] = value

    if missing:
        print(
            f"  WARNING: Skipping {path.relative_to(REPO_ROOT)} — "
            f"missing required fields: {missing}",
            file=sys.stderr,
        )
        return None

    for field in OPTIONAL_FIELDS:
        value = data.get(field)
        if value is not None:
            entry[field] = value

    return entry


def collect_rules(rules_dir: Path) -> list[dict]:
    entries: list[dict] = []

    if not rules_dir.exists():
        print(f"ERROR: rules/ directory not found at {rules_dir}", file=sys.stderr)
        sys.exit(1)

    yaml_files = sorted(rules_dir.rglob("*.yaml")) + sorted(rules_dir.rglob("*.yml"))
    # Deduplicate (rglob patterns can overlap)
    seen: set[Path] = set()
    unique_files: list[Path] = []
    for f in yaml_files:
        if f not in seen:
            seen.add(f)
            unique_files.append(f)

    for path in unique_files:
        try:
            data = load_yaml(path)
        except yaml.YAMLError as exc:
            print(
                f"  WARNING: Skipping {path.relative_to(REPO_ROOT)} — YAML error: {exc}",
                file=sys.stderr,
            )
            continue

        if not is_rule_file(data):
            # Skip profiles or unknown documents silently
            continue

        entry = extract_entry(data, path)
        if entry is not None:
            entries.append(entry)

    return entries


def sort_entries(entries: list[dict]) -> list[dict]:
    return sorted(entries, key=lambda e: (e.get("category", ""), e.get("rule_id", "")))


def build_index_document(entries: list[dict]) -> dict:
    return {
        "schema_version": "agentshield-index-v0.1",
        "generated_by": "scripts/generate_index.py",
        "rule_count": len(entries),
        "rules": entries,
    }


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> int:
    print(f"Scanning {RULES_DIR} for rule files...")

    entries = collect_rules(RULES_DIR)
    entries = sort_entries(entries)

    index_doc = build_index_document(entries)

    # Dump with explicit block style so the YAML is readable
    output = yaml.dump(
        index_doc,
        default_flow_style=False,
        sort_keys=False,
        allow_unicode=True,
    )

    OUTPUT_PATH.write_text(output, encoding="utf-8")

    print(f"Wrote {len(entries)} rules to {OUTPUT_PATH.relative_to(REPO_ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
