# Contributing to claude-blue

Thanks for contributing. This guide covers the skill format, quality bar, and review process.

## Quick Rules

1. **One skill, one surface.** Prefer focused skills (`defensive-kerberos-detection`) over monoliths.
2. **Frontmatter required.** Skills without valid YAML frontmatter won't load.
3. **Accuracy over volume.** Every event ID, field name, command flag, and query must be verified against vendor documentation or tested in a lab. Mark version-specific behavior.
4. **Cite sources.** ATT&CK/D3FEND IDs, vendor docs, standards, research.
5. **No real data.** No customer logs, live credentials, real victim infrastructure, or personal data. Use sanitized or synthetic samples (RFC 5737 IPs: `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`; `example.com`).
6. **Code blocks are language-tagged** (`bash`, `powershell`, `kql`, `spl`, `yaml`, `xml`, `json`, `sql`, `text`, …).

---

## Skill Format

Path: `Skills/<category>/<skill-name>/SKILL.md`. The folder name **must** equal `name:`.

### Frontmatter

```yaml
---
name: defensive-<surface>
description: "What it covers, which data sources/tools/platforms, and when to use it. Dense with terms an analyst would type (event IDs, tool names, ATT&CK IDs, product names). Max 1024 characters, no angle brackets."
---
```

The `description` drives automatic loading — it is the most important line in the file. Optional Claude Code fields (`user-invocable`, `disable-model-invocation`, `argument-hint`, `allowed-tools`) are used only in the core router.

### Body Structure

```markdown
# <Skill Title>

<One paragraph: what this defends and why.>

## Quick Workflow
1. <ordered steps>

---

## <Sections per phase / technique cluster>
<Tables, commands, queries — annotated with why>

---

## Engagement Cheatsheet
<copy-paste sequence summarizing the method>

---

## Key References
- Standards, vendor docs, research
- Related: `defensive-...` skills
```

### Style

- Technical, imperative, present tense; no filler
- Tables for reference data (event IDs, mappings, decision matrices)
- Every detection lists required telemetry and known false positives
- Every response action states blast radius and reversibility
- State dates for time-sensitive facts ("as of Oct 2026")
- No emoji except ✓ ✗ ⚠ in tables

---

## Adding a Skill

1. Choose a category folder (propose a new one in the PR if needed)
2. Create `Skills/<category>/<skill-name>/SKILL.md`
3. Add it to the README skill index and the router table in `Skills/core/claude-blue/SKILL.md`
4. Add a `CHANGELOG.md` entry
5. Run:
   ```bash
   bash tools/check-skill.sh
   python3 tools/build_manifest.py
   ```
6. For detections: include TP/FP sample events and validator output (`sigma check`, `wazuh-logtest`, `suricata -T`, `yr check`)

## Modifying a Skill

- Keep `name:` stable (renames break installs)
- Note substantive changes in `CHANGELOG.md`
- When updating time-sensitive facts, update the router's *Current-State Notes* table

## Review Criteria

- Technical accuracy and currency
- Clarity for an analyst on shift
- Scope (one surface)
- Sources cited
- Safety: no real targets/data, no destructive defaults without warnings, offensive detail limited to what defense requires

AI-assisted drafting is welcome; human verification of every technical claim is required.
