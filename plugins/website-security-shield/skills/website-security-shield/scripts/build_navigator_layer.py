#!/usr/bin/env python3
"""
build_navigator_layer.py - generate a MITRE ATT&CK Navigator layer from the
mitre_attack technique list in SKILL.md frontmatter. The resulting
mappings/attack-navigator-layer.json can be loaded at
https://mitre-attack.github.io/attack-navigator/ to visualize coverage.

Run from the skill root. Sends no traffic. Requires PyYAML.
"""
import json
import os
import sys

try:
    import yaml
except ImportError:
    print("PyYAML required: pip install pyyaml", file=sys.stderr)
    sys.exit(1)

# Short comments per technique (why it's in scope for this skill).
COMMENTS = {
    "T1595": "Active scanning / recon (recon-and-discovery.md)",
    "T1592": "Host fingerprinting (recon-and-discovery.md)",
    "T1589": "Identity OSINT (recon-and-discovery.md)",
    "T1190": "Exploit public-facing app: all injection/RCE classes (exploitation-methodology.md)",
    "T1078": "Valid accounts / credential stuffing / ATO (auth-session-testing.md)",
    "T1110": "Brute force / lockout testing (auth-session-testing.md)",
    "T1556": "Auth bypass (exploitation + auth-session-testing.md)",
    "T1539": "Steal web session cookie (auth-session-testing.md)",
    "T1552": "Unsecured credentials / secrets in code (code_scan.py)",
    "T1505.003": "Web shell via file upload (exploitation-methodology.md)",
    "T1195": "Supply chain / dependencies (code-audit-guide.md, infrastructure-and-cloud.md)",
    "T1136": "Backdoor admin account persistence (incident-response.md)",
    "T1552.005": "Cloud metadata via SSRF (exploitation-methodology.md)",
    "T1526": "Cloud service discovery (infrastructure-and-cloud.md)",
    "T1567": "Exfiltration over web service (attack-surface-catalog.md)",
    "T1499": "Endpoint DoS (attack-surface-catalog.md, infrastructure-and-cloud.md)",
}


def main():
    if not os.path.exists("SKILL.md"):
        print("Run from the skill root (SKILL.md not found).", file=sys.stderr)
        sys.exit(2)
    fm = yaml.safe_load(open("SKILL.md", encoding="utf-8").read().split("---", 2)[1])
    techs = fm.get("frameworks", {}).get("mitre_attack", [])
    layer = {
        "name": "Website Security Shield coverage",
        "versions": {"attack": "15", "navigator": "4.9.0", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": "Techniques this skill helps find (authorized) and defend/detect. Anchored on T1190.",
        "sorting": 3,
        "hideDisabled": False,
        "techniques": [
            {"techniqueID": t, "score": 100, "color": "",
             "comment": COMMENTS.get(t, ""), "enabled": True}
            for t in techs
        ],
        "gradient": {"colors": ["#ffffff", "#66b1ff", "#0b5cad"], "minValue": 0, "maxValue": 100},
        "legendItems": [{"label": "Covered by this skill", "color": "#0b5cad"}],
        "metadata": [{"name": "source", "value": "SKILL.md frontmatter frameworks.mitre_attack"}],
    }
    os.makedirs("mappings", exist_ok=True)
    out = os.path.join("mappings", "attack-navigator-layer.json")
    with open(out, "w", encoding="utf-8", newline="\n") as f:
        json.dump(layer, f, indent=2)
        f.write("\n")
    print(f"Wrote {out}: {len(techs)} techniques.")


if __name__ == "__main__":
    main()
