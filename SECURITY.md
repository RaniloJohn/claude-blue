# Security Policy

## Reporting

Report security issues privately via GitHub Security Advisories ("Report a vulnerability" on the repository's Security tab). Do not open public issues for:

- A real credential, token, or customer/victim data accidentally included in a skill or example
- Content that could cause unsafe outcomes if followed (e.g., a containment command with destructive defaults and no warning)
- Malicious changes to `install.sh`, tools, or CI workflows

Expect acknowledgement within 7 days.

## Scope

claude-blue is documentation and helper scripts. The skills instruct an AI model; they do not execute code by themselves. `install.sh` only copies or symlinks files into a skills directory — review it before running, as with any script.

## Safe Use

- Test detections and commands in non-production environments first
- Containment actions require organizational approval
- Use only on systems you are authorized to defend
