# Threat model

## Assets

Source files, credentials, personal information, wrapped DEKs, master key, local audit records, and blockchain signing authority.

## Adversaries

Accidental prompt disclosure, malicious repository content, untrusted MCP caller, local process with filesystem access, stolen machine, and blockchain observer.

## Controls in this prototype

- MCP path allowlist.
- Source-preserving redaction and no-overwrite output behavior.
- AES-256-GCM with fresh per-operation DEKs/nonces and authenticated operation ID.
- DEK wrapping under local master key.
- Local audit hash chain and salted commitment helper.
- No plaintext or keys intentionally sent to chain.

## Out of scope / not guaranteed

- Complete detection or anonymization.
- Protection from root/admin or malware running as the same user.
- Protection if master key is stolen or exposed in memory.
- Enforcing policy on tools that bypass MCP.
- Secure deletion on SSDs, copy-on-write filesystems, backups, swap, or process memory.
- Compliance certification or suitability as the sole PHI control.
