# Architecture

1. CLI, dashboard, and MCP call the shared service layer.
2. Scanner walks an explicitly supplied directory, skips known generated directories and symlinks, caps individual files at 2 MiB, and reports binary/oversize files as uninspected rather than safe.
3. Sanitizer creates a separate redacted text file; source is never overwritten.
4. Crypto service generates a fresh AES-256 DEK and nonce per operation; a local master key wraps the DEK. The envelope carries the wrapped DEK and ciphertext. The operation ID is authenticated additional data.
5. Audit module appends a hash-chained JSONL event log with minimal metadata.
6. Solidity registry accepts salted batch commitments. Automatic on-chain submission is intentionally not enabled in this prototype.

## Production hardening backlog

- OS keychain/KMS integration and key rotation/versioning.
- Streaming encryption for large files; secure temp-file lifecycle.
- Better structured-data parsers and secret detectors, Luhn validation, language-aware parsing, and benchmarked detection metrics.
- Authentication and authorization for HTTP; strict path allowlists; CSRF/SSRF protections where relevant.
- Remote MCP deployment with TLS/OAuth, tenant separation, rate limits, audit retention policy, and explicit consent.
- OS-level enforcement/sandboxing to prevent bypass through shell or alternate file tools.
- Database-backed structured audit store, append-only storage, Merkle proofs, and reviewed transaction publisher.
- Independent penetration test and contract audit.
