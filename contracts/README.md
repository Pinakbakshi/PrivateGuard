# Solidity audit registry

Requires Foundry and OpenZeppelin Contracts. From this directory:

```bash
forge install foundry-rs/forge-std --no-commit
forge install OpenZeppelin/openzeppelin-contracts --no-commit
forge test
anvil
```

For a local deployment, set environment variables in your shell (never commit them):

```bash
export PRIVATEGUARD_DEPLOYER_PRIVATE_KEY=... # throwaway Anvil key only
export PRIVATEGUARD_REGISTRY_ADMIN=0x...     # local admin address
forge script script/Deploy.s.sol:DeployPrivacyAuditRegistry --rpc-url http://127.0.0.1:8545 --broadcast
```

The contract stores only batch IDs and commitments. Use randomly salted commitments; keep the salt and event preimage off-chain. A production deployment needs a threat-model review, admin key management, and operational controls.
