#!/usr/bin/env bash
# claude-blue installer — copies (or symlinks) skills into a Claude skills directory.
# Claude discovers skills one level deep: <target>/<skill-name>/SKILL.md, so skills are flattened.
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SKILLS_DIR="$REPO_DIR/Skills"
TARGET="${HOME}/.claude/skills"
CATEGORY=""
SKILL=""
MODE="copy"
CORE_ONLY=0
LIST=0
FORCE=0

usage() {
  cat <<'USAGE'
Usage: ./install.sh [options]

  --target DIR        Install directory (default: ~/.claude/skills; project: .claude/skills)
  --category NAME     Install one category (e.g. soc, detection, ir). Repeatable via comma list.
  --skill NAME        Install one skill by name (e.g. defensive-sigma). Comma list allowed.
  --core-only         Install only the claude-blue router skill
  --link              Symlink instead of copy (stays in sync with git pull)
  --force             Overwrite existing skill folders
  --list              List categories and skills, then exit
  -h, --help          Show this help

Examples:
  ./install.sh                                  # all skills to ~/.claude/skills
  ./install.sh --target .claude/skills          # project-level install
  ./install.sh --category soc,detection,siem    # selected categories (+ core router)
  ./install.sh --skill defensive-wazuh --link   # one skill, symlinked
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --target)    TARGET="$2"; shift 2 ;;
    --category)  CATEGORY="$2"; shift 2 ;;
    --skill)     SKILL="$2"; shift 2 ;;
    --core-only) CORE_ONLY=1; shift ;;
    --link)      MODE="link"; shift ;;
    --force)     FORCE=1; shift ;;
    --list)      LIST=1; shift ;;
    -h|--help)   usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage; exit 1 ;;
  esac
done

if [[ $LIST -eq 1 ]]; then
  for cat_dir in "$SKILLS_DIR"/*/; do
    cat_name="$(basename "$cat_dir")"
    echo "[$cat_name]"
    for s in "$cat_dir"*/; do echo "  $(basename "$s")"; done
  done
  exit 0
fi

selected=()
if [[ $CORE_ONLY -eq 1 ]]; then
  selected+=("$SKILLS_DIR/core/claude-blue")
elif [[ -n "$SKILL" ]]; then
  IFS=',' read -ra names <<< "$SKILL"
  for n in "${names[@]}"; do
    match=$(find "$SKILLS_DIR" -mindepth 2 -maxdepth 2 -type d -name "$n" | head -1)
    [[ -z "$match" ]] && { echo "Skill not found: $n" >&2; exit 1; }
    selected+=("$match")
  done
elif [[ -n "$CATEGORY" ]]; then
  IFS=',' read -ra cats <<< "$CATEGORY"
  selected+=("$SKILLS_DIR/core/claude-blue")
  for c in "${cats[@]}"; do
    [[ -d "$SKILLS_DIR/$c" ]] || { echo "Category not found: $c" >&2; exit 1; }
    for s in "$SKILLS_DIR/$c"/*/; do selected+=("${s%/}"); done
  done
else
  for s in "$SKILLS_DIR"/*/*/; do selected+=("${s%/}"); done
fi

mkdir -p "$TARGET"
installed=0; skipped=0
declare -A seen=()
for src in "${selected[@]}"; do
  name="$(basename "$src")"
  [[ -n "${seen[$name]:-}" ]] && continue
  seen[$name]=1
  [[ -f "$src/SKILL.md" ]] || { echo "Missing SKILL.md in $src" >&2; continue; }
  dest="$TARGET/$name"
  if [[ -e "$dest" || -L "$dest" ]]; then
    if [[ $FORCE -eq 1 ]]; then rm -rf "$dest"; else echo "skip (exists): $name  — use --force to overwrite"; skipped=$((skipped+1)); continue; fi
  fi
  if [[ "$MODE" == "link" ]]; then ln -s "$src" "$dest"; else cp -R "$src" "$dest"; fi
  installed=$((installed+1))
done

echo "claude-blue: installed $installed skill(s) to $TARGET ($MODE), skipped $skipped."
echo "Verify in Claude Code: type /claude-blue"
