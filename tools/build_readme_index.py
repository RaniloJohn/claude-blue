#!/usr/bin/env python3
"""Generate the Categories table and Skill Index for README.md.

Usage: python3 tools/build_readme_index.py > /tmp/index.md
Summaries: tools/skill_summaries.json (skill -> one-line summary).
"""
import json
import pathlib

ROOT = pathlib.Path(__file__).resolve().parent.parent
SUMMARIES = json.loads((ROOT / "tools" / "skill_summaries.json").read_text())

# (folder, display name, focus)
CATEGORIES = [
    ("core", "Core", "Router, principles, workflows W1–W8, templates"),
    ("research", "Research", "Research-first methodology, CVE research & coordinated disclosure"),
    ("defense-model", "Defense Model", "Fundamentals, defense in depth, zero trust, architecture, kill chain, D3FEND, resilience"),
    ("soc", "SOC Operations", "Triage, log sources & parsing, playbooks, SOAR, SOC build, metrics, UEBA"),
    ("detection", "Detection Engineering", "Sigma, YARA/YARA-X, Suricata/Snort, query languages, detection-as-code"),
    ("detection-packs", "ATT&CK Detection Packs", "One pack per ATT&CK tactic: telemetry, rules, FPs, triage"),
    ("siem", "SIEM & XDR Platforms", "Wazuh, Elastic, Splunk, Sentinel, Security Onion, Graylog, QRadar, Google SecOps, Defender XDR, CrowdStrike, SentinelOne"),
    ("hunting", "Threat Hunting", "Methodology, Windows hunts, network hunts"),
    ("ir", "Incident Response", "IR command, live response, ransomware, BEC, cloud IR"),
    ("forensics", "Digital Forensics", "Windows, Linux, macOS, memory, timelines"),
    ("malware", "Malware Analysis", "Static triage, dynamic analysis, malicious documents"),
    ("cti", "Threat Intelligence", "CTI, ATT&CK/D3FEND mapping, IOC management"),
    ("endpoint", "Endpoint", "Windows event logs, Sysmon, Linux telemetry, EDR tuning, Windows hardening, application control"),
    ("active-directory", "Active Directory", "AD/AD CS hardening, attack detection, forest recovery"),
    ("identity", "Identity", "Entra ID, secure auth implementation"),
    ("appsec", "Application Security", "Secure code review, WAF, API security, SAST/DAST"),
    ("network", "Network Security", "Architecture, NGFW, IDS/IPS, NDR, forensics, DNS, proxy/TLS, ZTNA, VPN, NAC, IPv6, BGP, SASE, DDoS, PKI, L2, segmentation"),
    ("wireless", "Wireless", "WIDS, secure Wi-Fi design"),
    ("cloud", "Cloud", "AWS, Azure, GCP, CSPM/IaC"),
    ("container", "Container & Kubernetes", "Container hardening, Kubernetes security"),
    ("supply-chain", "Supply Chain & CI/CD", "Pipeline hardening, secrets, SBOM/SLSA"),
    ("vuln-mgmt", "Vulnerability Management", "Risk-based prioritization, patching, asset inventory, testing programs, PSIRT & disclosure handling"),
    ("hardening", "Hardening", "Linux, Cisco/Huawei network devices"),
    ("email", "Email Security", "SPF/DKIM/DMARC, phishing triage"),
    ("deception", "Deception", "Honeytokens, honey accounts, honeypots"),
    ("ot", "OT/ICS", "Purdue/IEC 62443, ICS protocol monitoring"),
    ("ai", "AI Security", "LLM & agent security (OWASP LLM + Agentic Top 10)"),
    ("human", "Human & Physical", "Security awareness, physical security"),
    ("purple", "Purple Team", "Detection validation, adversary emulation"),
    ("grc", "GRC", "Framework mapping, threat modeling & risk"),
    ("utility", "Utility", "IR reporting, 30-minute compromise checks"),
    ("tools", "Tools", "Doc-verified safe operation of 22 tool families + tool-safety umbrella"),
]


def anchor(title: str) -> str:
    out = []
    for ch in title.lower():
        if ch.isalnum() or ch in "-_ ":
            out.append("-" if ch == " " else ch)
    return "".join(out)


def skills_in(folder: str):
    return sorted(p.parent.name for p in (ROOT / "Skills" / folder).glob("*/SKILL.md"))


def main():
    folders = {p.name for p in (ROOT / "Skills").iterdir() if p.is_dir()}
    listed = {c[0] for c in CATEGORIES}
    missing = folders - listed
    if missing:
        raise SystemExit(f"categories missing from CATEGORIES: {sorted(missing)}")

    total = 0
    lines = ["| Category | Skills | Focus |", "|---|---:|---|"]
    for folder, name, focus in CATEGORIES:
        n = len(skills_in(folder))
        total += n
        lines.append(f"| [{name}](#{anchor(name)}) | {n} | {focus} |")
    lines.append(f"| **Total** | **{total}** | |")
    print("\n".join(lines))
    print("\n---\n\n## Skill Index\n")
    for folder, name, _ in CATEGORIES:
        print(f"### {name}\n\n`Skills/{folder}/`\n")
        print("| Skill | What it covers |\n|---|---|")
        for sk in skills_in(folder):
            summ = SUMMARIES.get(sk)
            if not summ:
                raise SystemExit(f"no summary for {sk}")
            print(f"| [`{sk}`](Skills/{folder}/{sk}/SKILL.md) | {summ} |")
        print()


if __name__ == "__main__":
    main()
