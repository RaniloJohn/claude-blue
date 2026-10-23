#!/usr/bin/env python3
"""Generate claude-skills.json from Skills/<category>/<skill>/SKILL.md frontmatter."""
import json, os, re, sys
from datetime import date

try:
    import yaml
except ImportError:
    sys.exit("pyyaml required: pip install pyyaml")

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SKILLS = os.path.join(ROOT, "Skills")

skills = []
for cat in sorted(os.listdir(SKILLS)):
    cdir = os.path.join(SKILLS, cat)
    if not os.path.isdir(cdir):
        continue
    for name in sorted(os.listdir(cdir)):
        path = os.path.join(cdir, name, "SKILL.md")
        if not os.path.isfile(path):
            continue
        text = open(path, encoding="utf-8").read()
        m = re.match(r"^---\n(.*?)\n---\n", text, re.S)
        fm = yaml.safe_load(m.group(1)) if m else {}
        skills.append({
            "name": fm.get("name", name),
            "category": cat,
            "path": os.path.relpath(path, ROOT).replace(os.sep, "/"),
            "description": fm.get("description", ""),
            "lines": text.count("\n"),
        })

manifest = {
    "name": "claude-blue",
    "description": "Defensive security skills for Claude — SOC, detection engineering, threat hunting, DFIR, hardening.",
    "license": "MIT",
    "generated": date.today().isoformat(),
    "skill_count": len(skills),
    "categories": sorted({s["category"] for s in skills}),
    "skills": skills,
}
out = os.path.join(ROOT, "claude-skills.json")
with open(out, "w", encoding="utf-8") as f:
    json.dump(manifest, f, indent=2, ensure_ascii=False)
    f.write("\n")
print(f"wrote {out}: {len(skills)} skills")
