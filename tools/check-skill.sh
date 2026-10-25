#!/usr/bin/env bash
# Lint one or more SKILL.md files (or all if none given).
# Checks: frontmatter present, name == folder, description length 1..1024, no angle brackets in description,
# required sections present, language tags on code fences.
set -uo pipefail
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
files=("$@")
[[ ${#files[@]} -eq 0 ]] && mapfile -t files < <(find "$REPO_DIR/Skills" -name SKILL.md | sort)

python3 - "${files[@]}" <<'PY'
import sys, re, os
try:
    import yaml
except ImportError:
    sys.exit("pyyaml required: pip install pyyaml")
fail = 0
for p in sys.argv[1:]:
    t = open(p, encoding="utf-8").read()
    errs = []
    m = re.match(r'^---\n(.*?)\n---\n', t, re.S)
    if not m:
        errs.append("missing YAML frontmatter")
    else:
        try:
            fm = yaml.safe_load(m.group(1)) or {}
        except yaml.YAMLError as e:
            fm = {}; errs.append(f"invalid YAML: {e}")
        folder = os.path.basename(os.path.dirname(p))
        if fm.get("name") != folder:
            errs.append(f"name '{fm.get('name')}' != folder '{folder}'")
        if not re.fullmatch(r"[a-z0-9-]{1,64}", str(fm.get("name", ""))):
            errs.append("name must be lowercase letters, digits, hyphens (<=64)")
        d = str(fm.get("description", ""))
        if not d: errs.append("missing description")
        if len(d) > 1024: errs.append(f"description too long ({len(d)} > 1024)")
        if "<" in d or ">" in d: errs.append("angle brackets in description")
    body = t[m.end():] if m else t
    for sec in ("## Engagement Cheatsheet", "## Key References"):
        if sec not in body and os.path.basename(os.path.dirname(p)) != "claude-blue":
            errs.append(f"missing section '{sec}'")
    fences = re.findall(r'^```(.*)$', body, re.M)
    opening = fences[0::2]
    untagged = sum(1 for f in opening if f.strip() == "")
    if untagged: errs.append(f"{untagged} code fence(s) without language tag")
    if len(fences) % 2: errs.append("unbalanced code fences")
    status = "OK " if not errs else "ERR"
    print(f"[{status}] {os.path.relpath(p)}")
    for e in errs: print(f"      - {e}")
    fail |= bool(errs)
sys.exit(1 if fail else 0)
PY
