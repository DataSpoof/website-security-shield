#!/usr/bin/env python3
"""
build_index.py - generate index.json: a machine-readable catalogue of this skill,
its reference modules, scripts and framework mappings. Run from the skill root.

Reads SKILL.md frontmatter (framework mappings, version, etc.) and enumerates
references/ and scripts/. Sends no traffic; touches nothing outside index.json.

Usage:  python scripts/build_index.py   (writes ./index.json)
Requires PyYAML.
"""
import datetime as dt
import json
import os
import sys

try:
    import yaml
except ImportError:
    print("PyYAML required: pip install pyyaml", file=sys.stderr)
    sys.exit(1)


def load_frontmatter(path):
    text = open(path, encoding="utf-8").read()
    if not text.startswith("---"):
        raise ValueError("SKILL.md missing frontmatter")
    fm = text.split("---", 2)[1]
    return yaml.safe_load(fm)


def first_heading_blurb(path):
    """Return the first non-empty prose line under the first '#' heading."""
    lines = open(path, encoding="utf-8").read().splitlines()
    seen_h = False
    for ln in lines:
        if ln.startswith("#"):
            seen_h = True
            continue
        if seen_h and ln.strip() and not ln.startswith(("#", "|", ">", "-", "`")):
            return ln.strip()
    return ""


def main():
    root = os.getcwd()
    skill_md = os.path.join(root, "SKILL.md")
    if not os.path.exists(skill_md):
        print("Run from the skill root (SKILL.md not found).", file=sys.stderr)
        sys.exit(2)
    fm = load_frontmatter(skill_md)

    refs = []
    ref_dir = os.path.join(root, "references")
    if os.path.isdir(ref_dir):
        for fn in sorted(os.listdir(ref_dir)):
            if fn.endswith(".md"):
                refs.append({"file": f"references/{fn}",
                             "title": first_heading_blurb(os.path.join(ref_dir, fn)) or fn})

    scripts = []
    sc_dir = os.path.join(root, "scripts")
    if os.path.isdir(sc_dir):
        for fn in sorted(os.listdir(sc_dir)):
            if fn.endswith(".py") and not fn.startswith("build_index"):
                doc = ""
                with open(os.path.join(sc_dir, fn), encoding="utf-8") as f:
                    src = f.read()
                if '"""' in src:
                    doc = src.split('"""')[1].strip().splitlines()[0]
                scripts.append({"file": f"scripts/{fn}", "summary": doc})

    assets = []
    as_dir = os.path.join(root, "assets")
    if os.path.isdir(as_dir):
        for fn in sorted(os.listdir(as_dir)):
            assets.append(f"assets/{fn}")

    index = {
        "name": fm["name"],
        "version": fm.get("version", "0.0.0"),
        "domain": fm.get("domain", ""),
        "subdomain": fm.get("subdomain", ""),
        "author": fm.get("author", ""),
        "license": fm.get("license", ""),
        "tags": fm.get("tags", []),
        "description": " ".join(fm.get("description", "").split()),
        "frameworks": fm.get("frameworks", {}),
        "modules": {"references": refs, "scripts": scripts, "assets": assets},
        "generated_at": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    with open(os.path.join(root, "index.json"), "w", encoding="utf-8", newline="\n") as f:
        json.dump(index, f, indent=2)
        f.write("\n")
    print(f"Wrote index.json: {len(refs)} references, {len(scripts)} scripts, "
          f"{len(index['frameworks'].get('mitre_attack', []))} ATT&CK techniques.")


if __name__ == "__main__":
    main()
