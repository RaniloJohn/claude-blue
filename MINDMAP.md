# claude-blue Mind Map

```mermaid
mindmap
  root((claude-blue))
    Core
      claude-blue
    Research
      blue-research
    Defense Model
      active-defense
      cyber-resilience
      d3fend-countermeasures
      defense-in-depth
      kill-chain-defense
      security-architecture
      security-fundamentals
      security-operating-model
      threat-informed-defense
      zero-trust-architecture
    SOC Operations
      alert-triage
      log-parsing
      log-sources
      security-metrics
      soar-automation
      soc-building
      soc-playbooks
      ueba
    Detection Engineering
      detection-as-code
      query-languages
      sigma
      suricata-snort
      yara
    ATTandCK Detection Packs
      detect-collection
      detect-command-and-control
      detect-credential-access
      detect-defense-evasion
      detect-discovery
      detect-execution
      detect-exfiltration
      detect-impact
      detect-initial-access
      detect-lateral-movement
      detect-persistence
      detect-privilege-escalation
    SIEM and XDR Platforms
      crowdstrike-falcon
      defender-xdr
      elastic
      google-secops
      graylog
      qradar
      security-onion
      sentinel
      sentinelone
      splunk
      wazuh
    Threat Hunting
      hunt-network
      hunt-windows
      threat-hunting
    Incident Response
      bec-response
      cloud-ir
      incident-response
      live-response
      ransomware-response
    Digital Forensics
      linux-forensics
      macos-forensics
      memory-forensics
      timeline-analysis
      windows-forensics
    Malware Analysis
      dynamic-analysis
      maldoc-analysis
      malware-triage
    Threat Intelligence
      attack-mapping
      cti
      ioc-management
    Endpoint
      edr-tuning
      linux-telemetry
      sysmon
      windows-event-logs
      windows-hardening
    Active Directory
      ad-detection
      ad-forest-recovery
      ad-hardening
    Identity
      auth-implementation
      entra-id
    Application Security
      api-security
      sast-dast
      secure-code-review
      waf
    Network Security
      ddos
      dns-security
      firewall-analysis
      ids-ips-deployment
      ipv6-security
      l2-security
      nac
      netflow-ndr
      network-forensics
      network-security-architecture
      network-segmentation
      ngfw-policy
      pcap-analysis
      proxy-tls-inspection
      remote-access-ztna
      routing-security
      sdwan-sase
      tls-pki
      vpn-ipsec
      zeek
    Wireless
      wireless-design
      wireless-ids
    Cloud
      aws-security
      azure-security
      cspm
      gcp-security
    Container and Kubernetes
      container-hardening
      k8s-security
    Supply Chain and CI/CD
      cicd-hardening
      sbom-slsa
      secrets-management
    Vulnerability Management
      patch-management
      vuln-management
    Hardening
      linux-hardening
      network-device-hardening
    Email Security
      email-auth
      phishing-triage
    Deception
      deception
    OT/ICS
      ics-security
    AI Security
      ai-security
    Purple Team
      adversary-emulation
      purple-team
    GRC
      frameworks
      risk-threat-modeling
    Utility
      ir-reporting
      quick-checks
    Tools
      tool-ad-assessment
      tool-cloud-posture
      tool-container-scanners
      tool-cyberchef
      tool-dast-scanners
      tool-emulation
      tool-falco
      tool-hayabusa-chainsaw
      tool-honeypots
      tool-kape-eztools
      tool-misp-opencti
      tool-nmap
      tool-osquery
      tool-plaso
      tool-safety
      tool-sast
      tool-secret-scanners
      tool-sigstore-cosign
      tool-sysinternals
      tool-thehive-cortex
      tool-velociraptor
      tool-volatility3
      tool-wazuh
```

## Workflow Map

```mermaid
flowchart LR
    A[Alert / Logs] --> W1[W1 Triage & IR]
    B[CVE / Report / TTP] --> W2[W2 Detection Engineering]
    C[Actor / TTP / Asset] --> W3[W3 Threat Hunting]
    D[Artifacts / Memory] --> W4[W4 DFIR Reconstruction]
    E[CVE list / Scans] --> W5[W5 Prioritization]
    F[Config / Baseline] --> W6[W6 Hardening Review]
    G[Architecture / Network design] --> W7[W7 Defense Architecture]
    H[Should we...? / Tool / Product / CVE] --> W8[W8 Research & Recommendation]
    W8 -->|verified facts| W2
    W8 -->|decision| W6
    W7 -->|gaps| W6
    W1 -->|TP| IR[Containment & Eradication]
    W3 -->|finding| W1
    W3 -->|pattern| W2
    W4 -->|IOCs| W3
    IR -->|lessons| W2
    W2 -->|validate| PT[Purple Team]
    PT -->|gaps| W2
```
