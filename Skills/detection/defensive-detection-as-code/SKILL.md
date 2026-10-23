---
name: defensive-detection-as-code
description: "Detection-as-Code (DaC) engineering lifecycle: version-controlled detection repos, rule schemas, peer review, unit tests with true/false positive samples, CI/CD pipelines (GitHub Actions, GitLab CI) that lint, convert, and deploy Sigma/SPL/KQL/EQL/Wazuh/YARA rules via API, staging (log-only) promotion, detection metadata, ATT&CK v18 coverage tracking, detection quality metrics, and continuous validation with Atomic Red Team. Use when building or reviewing a detection engineering program or pipeline."
---

# Detection-as-Code

Treat detections like software: source control, review, tests, CI, staged rollout, metrics, deprecation. The goal is detections that are trusted, measured, and cheap to change.

## Quick Workflow

1. Repo with one canonical format (Sigma) + platform-native exceptions
2. Metadata schema enforced by linter
3. Unit tests: TP and FP samples per rule
4. CI: lint → convert → test → package
5. CD: deploy to staging (log-only) → promote after soak
6. Measure: fire rate, TP rate, MTTA; review quarterly

---

## 1. Repository Layout

```text
detections/
├── rules/
│   ├── windows/credential_access/lsass_access.yml        # Sigma
│   ├── cloud/aws/cloudtrail_stoplogging.yml
│   └── native/sentinel/entra_token_replay.kql            # platform-only logic
├── tests/
│   └── <rule-id>/
│       ├── tp_01.json
│       └── fp_01.json
├── pipelines/                    # pySigma custom field mappings
├── filters/                      # Sigma filters per environment
├── tools/ (lint.py, test_runner.py, deploy_*.py)
├── coverage/attack_layer.json    # ATT&CK Navigator layer, generated
└── .github/workflows/detections.yml
```

---

## 2. Metadata Schema (beyond Sigma core)

```yaml
custom:
  owner: detection-eng
  severity_rationale: "Credential theft on any host is SEV2+"
  data_sources: [sysmon:10, mde:DeviceEvents]
  triage_guide: docs/triage/lsass_access.md
  test_atomic: T1003.001-1
  deployed_to: [splunk-prod, sentinel-prod]
  review_by: 2027-01-31
```

Lint rejects rules missing: id, ATT&CK tag, falsepositives, level, data_sources, test sample.

---

## 3. CI Pipeline (GitHub Actions)

```yaml
name: detections
on:
  pull_request:
  push:
    branches: [main]
permissions:
  contents: read
jobs:
  validate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@<full-commit-sha>        # pin by SHA
      - uses: actions/setup-python@<full-commit-sha>
        with: { python-version: "3.12" }
      - run: pip install sigma-cli pySigma-backend-splunk pySigma-backend-kusto pySigma-backend-elasticsearch
      - run: sigma check rules/
      - run: python tools/lint.py rules/
      - run: |
          mkdir -p build
          sigma convert -t splunk -p sysmon rules/windows -o build/splunk.spl
          sigma convert -t kusto  -p microsoft_xdr rules/windows -o build/xdr.kql
          sigma convert -t lucene -p ecs_windows rules/windows -o build/elastic.lucene
      - run: python tools/test_runner.py --rules rules/ --tests tests/
  deploy-staging:
    needs: validate
    if: github.ref == 'refs/heads/main'
    environment: staging          # requires approval
    runs-on: ubuntu-latest
    steps:
      - run: python tools/deploy_splunk.py --mode log-only
```

Pin third-party actions to full commit SHAs (lesson of the tj-actions/changed-files compromise, CVE-2025-30066).

---

## 4. Testing Strategies

| Level | Method |
|---|---|
| Syntax | `sigma check`, `yr check`, `suricata -T`, `wazuh-logtest` |
| Logic | Evaluate rule against stored JSON events (pySigma + local evaluator, or Chainsaw/Hayabusa on sample EVTX) |
| Platform | Ingest samples to a dev index/workspace, run converted query |
| End-to-end | Atomic Red Team / Caldera in lab → confirm alert fires |
| Regression | Re-run all tests on every pipeline/field-mapping change |

Event sample corpora: Mordor/Security-Datasets (OTRF), EVTX-ATTACK-SAMPLES, your own sanitized lab captures.

---

## 5. Staged Rollout

| Stage | Behavior | Exit criteria |
|---|---|---|
| Experimental | Log-only, no alert | ≥7 d, volume known, FP sources listed |
| Test | Alerts to detection team queue | TP rate acceptable, triage guide written |
| Stable | Production SOC queue | Owner + review date set |
| Deprecated | Disabled, kept for history | Replacement linked |

---

## 6. Coverage Tracking

- Generate ATT&CK Navigator layer from rule tags each build
- ATT&CK v18 replaced Data Sources with **Detection Strategies → Analytics → Data Components**; map each rule to the relevant Detection Strategy ID for gap analysis
- Coverage ≠ protection: weight by test status (untested = 0) and data source health

---

## 7. Quality Metrics

| Metric | Use |
|---|---|
| Alerts/day per rule | Noise budget |
| TP rate (30 d) | Precision |
| Mean triage time | Analyst cost |
| Validation pass rate | Rule still fires vs emulation |
| Time from intel to deployed detection | Engineering velocity |
| Rules past review date | Hygiene |

---

## 8. Review Checklist (PR template)

```text
[ ] Behavior described; why attacker can't trivially evade
[ ] Required telemetry exists in prod (link to health dashboard)
[ ] TP + FP samples added; tests pass
[ ] Converted queries inspected per backend
[ ] Severity + triage guide
[ ] ATT&CK tags; Detection Strategy ID
[ ] Rollout stage set
```

---

## Engagement Cheatsheet

```text
branch → write Sigma + tests → PR → CI (lint/convert/test) → review
→ merge → staging log-only 7-14 d → promote → metrics → quarterly review
```

---

## Key References

- MITRE ATT&CK v18 Detection Strategies (Oct 2025)
- Atomic Red Team — https://github.com/redcanaryco/atomic-red-team
- OTRF Security-Datasets — https://github.com/OTRF/Security-Datasets
- Splunk security_content, elastic/detection-rules (DaC reference repos)
- CVE-2025-30066 (tj-actions/changed-files) — CI supply chain lesson
- Related: `defensive-sigma`, `defensive-purple-team`, `defensive-cicd-hardening`
