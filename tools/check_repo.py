"""Dependency-free offline checks for ANIE repository governance.

Structural guardrails only: not a full security review or secret scanner.
"""
from __future__ import annotations
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
REQUIRED = [
    "AGENTS.md", ".github/copilot-instructions.md", ".github/CODEOWNERS",
    ".github/PULL_REQUEST_TEMPLATE.md", ".github/dependabot.yml", "SECURITY.md",
    "docs/DEVELOPMENT_WORKFLOW.md", "docs/THREAT_MODEL.md",
    "docs/DATA_PUBLICATION_POLICY.md", "docs/RELEASE_PROCESS.md",
    "schemas/intelligence-v1.schema.json",
]
SKILLS = ["observation-contract", "model-evaluation", "collector-threat-model", "dataset-release"]
SHA_REF = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+@[0-9a-f]{40}$")


def inspect_skill(content: str, name: str) -> list[str]:
    if not content.startswith("---\n") or "\n---\n" not in content[4:]:
        return ["missing YAML frontmatter"]
    fields = {}
    for line in content.split("---", 2)[1].splitlines():
        if ":" in line:
            key, value = line.split(":", 1)
            fields[key.strip()] = value.strip()
    errors = []
    if fields.get("name") != name:
        errors.append("skill name must match folder")
    if not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", fields.get("name", "")):
        errors.append("invalid skill name")
    if not 1 <= len(fields.get("description", "")) <= 1024:
        errors.append("missing or overly long skill description")
    return errors


def inspect_workflow(content: str) -> list[str]:
    errors = []
    if "permissions:\n  contents: read" not in content:
        errors.append("missing least-privilege workflow permissions")
    for forbidden in (
        "pull_request_target:", "workflow_run:", "issue_comment:",
        "id-token: write", "contents: write", "secrets.", "runs-on: self-hosted",
    ):
        if forbidden in content:
            errors.append("privileged/secret workflow token: " + forbidden)
    uses = re.findall(r"(?m)^\s*-\s*uses:\s*([^\s#]+)", content)
    if not uses:
        errors.append("no pinned actions found")
    for item in uses:
        if not SHA_REF.fullmatch(item):
            errors.append("mutable/unknown action: " + item)
    return errors


def check(root: Path = ROOT) -> list[str]:
    errors = []
    for rel in REQUIRED:
        if not (root / rel).is_file():
            errors.append("missing required file: " + rel)
    for name in SKILLS:
        path = root / ".agents" / "skills" / name / "SKILL.md"
        if not path.is_file():
            errors.append("missing agent skill: " + name)
        else:
            errors += [name + ": " + msg for msg in inspect_skill(path.read_text(encoding="utf-8"), name)]
    agents = sorted((root / ".github/agents").glob("*.agent.md"))
    if len(agents) < 3:
        errors.append("fewer than three agent profiles")
    for agent in agents:
        content = agent.read_text(encoding="utf-8")
        if not content.startswith("---\n") or not re.search(r"(?m)^description:\s*\S", content):
            errors.append("agent missing description: " + agent.name)
    workflows = sorted((root / ".github/workflows").glob("*.yml"))
    if not workflows:
        errors.append("missing CI workflow")
    for path in workflows:
        errors += [path.name + ": " + msg for msg in inspect_workflow(path.read_text(encoding="utf-8"))]
    schema_path = root / "schemas/intelligence-v1.schema.json"
    if schema_path.is_file():
        try:
            schema = json.loads(schema_path.read_text(encoding="utf-8"))
            if schema.get("properties", {}).get("schema", {}).get("const") != "anie.intelligence.v1":
                errors.append("unexpected schema contract version")
        except (OSError, ValueError):
            errors.append("invalid schema JSON")
    return errors


def main() -> int:
    problems = check()
    for problem in problems:
        print("FAIL: " + problem)
    if problems:
        return 1
    print("PASS: offline ANIE repository structural guardrails (not a full security audit)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
