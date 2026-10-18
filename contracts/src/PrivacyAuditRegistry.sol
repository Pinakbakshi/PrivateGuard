// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {AccessControl} from "openzeppelin-contracts/contracts/access/AccessControl.sol";
import {Pausable} from "openzeppelin-contracts/contracts/utils/Pausable.sol";

/// @notice Stores salted commitments to off-chain PrivateGuard audit batches.
/// Never submit plaintext, personal data, paths, or encryption keys to this contract.
contract PrivacyAuditRegistry is AccessControl, Pausable {
    bytes32 public constant AUDITOR_ROLE = keccak256("AUDITOR_ROLE");
    mapping(bytes32 => bytes32) public commitments;

    event AuditAnchored(bytes32 indexed batchId, bytes32 indexed commitment, address indexed submitter, uint256 timestamp);

    error EmptyValue();
    error BatchAlreadyAnchored(bytes32 batchId);

    constructor(address admin) {
        if (admin == address(0)) revert EmptyValue();
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(AUDITOR_ROLE, admin);
    }

    function anchorAudit(bytes32 batchId, bytes32 commitment) external onlyRole(AUDITOR_ROLE) whenNotPaused {
        if (batchId == bytes32(0) || commitment == bytes32(0)) revert EmptyValue();
        if (commitments[batchId] != bytes32(0)) revert BatchAlreadyAnchored(batchId);
        commitments[batchId] = commitment;
        emit AuditAnchored(batchId, commitment, msg.sender, block.timestamp);
    }

    function verifyAudit(bytes32 batchId, bytes32 commitment) external view returns (bool) {
        return commitments[batchId] != bytes32(0) && commitments[batchId] == commitment;
    }

    function pause() external onlyRole(DEFAULT_ADMIN_ROLE) { _pause(); }
    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) { _unpause(); }
}
