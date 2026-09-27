#!/usr/bin/env python3
"""
validate_skill.py - CI validator for the Website Security Shield skill.

Checks every SKILL.md under plugins/**/skills/**:
  - frontmatter parses as YAML (PyYAML, never regex)
  - required fields present (name, description, version, license)
  - name is kebab-case and matches its directory
  - description length is sane
  - referenced framework mapping files exist
  - every file referenced from SKILL.md's "reference files" list exists
  - scripts import/parse (py_compile) and index.json is in sync
Exit non-zero on any failure. Requires PyYAML.
"""
import glob
import json
import os
import py_compile
import re
import sys

try:
    import yaml
except ImportError:
    print("::error::PyYAML required (pip install pyyaml)")
    sys.exit(1)

REQUIRED = ["name", "description", "version", "license"]
KEBAB = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")
errors, warnings = [], []


def err(m):
    errors.append(m)
    print(f"::error::{m}")


def warn(m):
    warnings.append(m)
    print(f"::warning::{m}")


def check_skill(skill_md):
    d = os.path.dirname(skill_md)
    text = open(skill_md, encoding="utf-8").read()
    if not text.startswith("---"):
        err(f"{skill_md}: missing frontmatter")
        return
    try:
        fm = yaml.safe_load(text.split("---", 2)[1])
    except yaml.YAMLError as e:
        err(f"{skill_md}: frontmatter is not valid YAML: {e}")
        return
    for k in REQUIRED:
        if not fm.get(k):
            err(f"{skill_md}: missing required frontmatter field '{k}'")
    name = fm.get("name", "")
    if name and not KEBAB.match(name):
        err(f"{skill_md}: name '{name}' is not kebab-case")
    if name and os.path.basename(d) != name:
        warn(f"{skill_md}: name '{name}' != directory '{os.path.basename(d)}'")
    desc = " ".join(fm.get("description", "").split())
    if len(desc) < 40:
        err(f"{skill_md}: description too short ({len(desc)} chars)")
    if len(desc) > 2000:
        warn(f"{skill_md}: description very long ({len(desc)} chars)")

    # framework mappings referenced -> mapping files should exist
    if fm.get("frameworks") and os.path.isdir(os.path.join(d, "mappings")):
        for f in ("mitre-attack.md", "owasp.md", "nist-csf.md"):
            if not os.path.exists(os.path.join(d, "mappings", f)):
                warn(f"{skill_md}: frameworks set but mappings/{f} missing")

    # every references/*.md mentioned in SKILL.md must exist
    for ref in re.findall(r"references/[A-Za-z0-9_\-]+\.md", text):
        if not os.path.exists(os.path.join(d, ref)):
            err(f"{skill_md}: references missing file '{ref}'")

    # scripts compile
    for py in glob.glob(os.path.join(d, "scripts", "*.py")):
        try:
            py_compile.compile(py, doraise=True)
        except py_compile.PyCompileError as e:
            err(f"{py}: does not compile: {e}")

    # index.json in sync (version + name), if present
    idx_path = os.path.join(d, "index.json")
    if os.path.exists(idx_path):
        try:
            idx = json.load(open(idx_path, encoding="utf-8"))
            if idx.get("version") != fm.get("version"):
                err(f"{idx_path}: version {idx.get('version')} != SKILL.md {fm.get('version')} (re-run build_index.py)")
            if idx.get("name") != name:
                err(f"{idx_path}: name mismatch (re-run build_index.py)")
        except json.JSONDecodeError as e:
            err(f"{idx_path}: invalid JSON: {e}")
    else:
        warn(f"{d}: no index.json (run scripts/build_index.py)")
    print(f"checked {skill_md}")


def main():
    roots = glob.glob("plugins/**/skills/**/SKILL.md", recursive=True) or glob.glob("**/SKILL.md", recursive=True)
    if not roots:
        err("no SKILL.md found")
    for s in sorted(roots):
        check_skill(s)
    print(f"\n{len(roots)} skill(s) · {len(errors)} error(s) · {len(warnings)} warning(s)")
    sys.exit(1 if errors else 0)


if __name__ == "__main__":
    main()
