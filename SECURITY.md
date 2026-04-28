# Security Policy

OmniWire coordinates remote nodes, MCP tools, browser automation, shell execution, sync, and local secrets. Treat its logs, tool output, config, databases, cookies, and environment variables as sensitive.

## Supported Versions

Security fixes target the latest `master` branch and the most recent npm release.

## Reporting a Vulnerability

Please report vulnerabilities privately when possible:

- Use GitHub's **Report a vulnerability** flow for this repository if available.
- Otherwise open a minimal issue that does not include secrets, live infrastructure details, private keys, cookies, or weaponized payloads.
- For coordination, contact `v0idch3cksum` on Discord.

## Sensitive Data Guidelines

- Never paste `OP_SERVICE_ACCOUNT_TOKEN`, SSH keys, cookies, TOTP seeds, session tokens, or `.omniwire-state/` contents into public issues.
- Redact hostnames, private IPs, usernames, vault names, database paths, and terminal transcripts before sharing diagnostics.
- If a token, cookie, SSH key, or TOTP seed may have appeared in tool output or logs, rotate it before sharing artifacts.
- Prefer 1Password or another secret manager for production secrets. Use file/env backends only for local development.
