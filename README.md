# PrivateGuard

Local-first privacy gateway for AI coding agents. It scans directories, classifies likely secrets/PII, creates sanitized copies, encrypts artifacts with a fresh AES-256-GCM data-encryption key (DEK) per operation, wraps each DEK with a local master key for recovery, and exposes narrow MCP tools. An optional Solidity registry anchors audit commitments.

> **Status:** portfolio MVP / security-sensitive prototype. It has not been independently audited. Detection is heuristic and cannot guarantee that all sensitive information is found. Do not use it as the sole control for production secrets, PHI, or regulated data.

## Security model and important limitations

- Scanning and encryption run locally. The server does not send files to an LLM or a blockchain.
- Each encryption operation generates a fresh 32-byte DEK and a fresh 12-byte AES-GCM nonce. The DEK is wrapped with a separately stored 32-byte master key.
- The default master key file is `~/.privateguard/master.key` with restrictive permissions on POSIX systems. This is a local MVP key store, not a hardware-backed vault. For production, replace it with macOS Keychain, Windows DPAPI/Credential Manager, a Linux secret service, or a KMS/HSM. Back up the master key securely: losing it makes wrapped DEKs unrecoverable; theft of it compromises stored DEKs.
- `sanitize_file` makes a separate sanitized copy and never overwrites the source. Redaction is irreversible; placeholder substitution is not yet implemented.
- The scanner uses regex/entropy heuristics. It can produce false positives and false negatives; encrypted, binary, unsupported, or unreadable files are not proven safe.
- MCP only mediates actions routed through its tools. It cannot magically intercept direct shell/file tools in Codex/Claude or other MCP clients. Restrict competing filesystem/shell tools and use client sandbox/approval controls if you need an enforcement boundary.
- The registry records commitments, not plaintext, keys, file paths, or finding details. Public chain data is permanent; even hashes can leak low-entropy data, so anchor only salted commitments.
- Blockchain anchoring is an optional module and is not wired to a signing wallet by default. No private key is bundled.

## Quick start (macOS/Linux)

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -e '.[dashboard,test]'
privateguard init
privateguard scan ./example-project --json
privateguard sanitize ./example-project/config.example --output ./artifacts/config.sanitized
privateguard encrypt ./example-project/sample.txt --output ./artifacts/sample.pga
privateguard decrypt ./artifacts/sample.pga --output ./artifacts/sample.recovered.txt
pytest -q
```

`privateguard init` creates the local state directory and master key. Do not commit `~/.privateguard`, encrypted artifacts, or the key file. On Windows, use `.venv\Scripts\activate`; POSIX permissions are best-effort on platforms that do not implement them.

## Dashboard

```bash
streamlit run dashboard/app.py
```

Enter a local directory path and click Scan. The dashboard calls the local API. In another terminal:

```bash
uvicorn privateguard.api:app --host 127.0.0.1 --port 8765
```

Keep the API bound to localhost unless you add authentication, TLS, authorization, and a hardened deployment model. Do not expose it to the public internet as-is.

## MCP server

The stdio MCP server exposes `scan_directory`, `sanitize_file`, `encrypt_file`, and `verify_audit`. Run it from the activated virtual environment:

```bash
privateguard-mcp
```

### Codex (local stdio)

Add to `~/.codex/config.toml` (adjust the absolute path to your venv executable):

```toml
[mcp_servers.privateguard]
command = "/ABSOLUTE/PATH/privateguard/.venv/bin/privateguard-mcp"
args = []
```

Restart Codex and inspect its MCP server list. Codex CLI, IDE extension, and ChatGPT desktop app may share Codex-host MCP configuration, depending on the client version.

### Claude Code (local stdio)

```bash
claude mcp add --scope user privateguard -- /ABSOLUTE/PATH/privateguard/.venv/bin/privateguard-mcp
claude mcp list
```

Run `/mcp` in Claude Code to inspect connection status. Exact CLI syntax may vary by release; confirm against the installed Claude Code version.

### ChatGPT

ChatGPT web custom MCP apps connect to a **remote reachable server or a supported Secure MCP Tunnel**, not a bare local stdio process. The local server in this repository is not directly connectable from ChatGPT web. To use it there, deploy a hardened remote Streamable HTTP MCP endpoint or tunnel the local service using a supported secure tunnel. Before remote deployment, add authentication, TLS, authorization, rate limiting, audit controls, and explicit path allowlists. Never expose an unauthenticated filesystem-scanning MCP server.

ChatGPT MCP availability depends on plan, workspace policy, and surface. Test in the intended workspace; this repository does not claim universal ChatGPT support.

## CLI commands

```text
privateguard init
privateguard scan PATH [--json]
privateguard sanitize FILE --output OUTPUT
privateguard encrypt FILE --output OUTPUT
privateguard decrypt FILE --output OUTPUT
privateguard verify-audit
```

The CLI only reads files inside the path explicitly supplied for a scan. MCP additionally requires configured allowed roots; by default the user must set `PRIVATEGUARD_ALLOWED_ROOTS` to a path-separator-delimited list before starting the MCP server. This avoids giving MCP callers unrestricted filesystem access.

Example:

```bash
export PRIVATEGUARD_ALLOWED_ROOTS="$HOME/dev:$HOME/Documents/safe-project"
privateguard-mcp
```

## Optional blockchain registry

`contracts/` contains a minimal Solidity registry. Use Foundry to test and deploy locally:

```bash
cd contracts
forge install OpenZeppelin/openzeppelin-contracts --no-commit
forge test
anvil
```

Deployment script and example configuration are in `contracts/script/`. Configure a signer only in your local environment or secret manager. Do not use a valuable wallet. Before public deployment, add external review, signer separation, rate limits, cost controls, and a defined commitment format.

The local audit log is a hash chain. The registry contract is a separate component; automatic anchoring needs a configured RPC endpoint, funded signer, deployed address, and a reviewed transaction submission implementation. This MVP intentionally does not silently submit local audit data on-chain.

## Files

- `src/privateguard/scanner.py` — bounded directory traversal and findings
- `src/privateguard/crypto_service.py` — AES-GCM encryption and wrapped DEKs
- `src/privateguard/policy.py` — sanitization
- `src/privateguard/audit.py` — local hash-chained audit log
- `src/privateguard/mcp_server.py` — stdio MCP tools with root allowlist
- `src/privateguard/api.py` — localhost FastAPI endpoints
- `dashboard/app.py` — Streamlit UI
- `contracts/` — Solidity audit registry and Foundry tests
- `tests/` — unit/security regression tests

## Threat model

Protects against accidental disclosure to an AI tool when tool access is correctly routed through PrivateGuard; accidental plaintext retention in ordinary logs; tampering with local audit entries; and ciphertext tampering. Does **not** by itself protect against a compromised OS/user account, memory dumps, malicious local processes, a stolen master key, a client bypassing MCP, undiscovered sensitive content, or an incorrectly configured remote deployment.

## License

MIT. See `LICENSE`.
