// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {PrivacyAuditRegistry} from "../src/PrivacyAuditRegistry.sol";

contract PrivacyAuditRegistryTest is Test {
    PrivacyAuditRegistry registry;
    address admin = address(0xA11CE);
    address writer = address(0xB0B);

    function setUp() public {
        vm.prank(admin);
        registry = new PrivacyAuditRegistry(admin);
        vm.prank(admin);
        registry.grantRole(registry.AUDITOR_ROLE(), writer);
    }

    function testAnchorAndVerify() public {
        bytes32 batch = keccak256("batch-1");
        bytes32 commitment = keccak256("salted commitment");
        vm.prank(writer);
        registry.anchorAudit(batch, commitment);
        assertTrue(registry.verifyAudit(batch, commitment));
        assertFalse(registry.verifyAudit(batch, keccak256("wrong")));
    }

    function testUnauthorizedWriterRejected() public {
        vm.expectRevert();
        registry.anchorAudit(keccak256("batch"), keccak256("commit"));
    }

    function testDuplicateBatchRejected() public {
        bytes32 batch = keccak256("batch");
        vm.prank(writer); registry.anchorAudit(batch, keccak256("first"));
        vm.prank(writer); vm.expectRevert(); registry.anchorAudit(batch, keccak256("second"));
    }

    function testPauseBlocksWrites() public {
        vm.prank(admin); registry.pause();
        vm.prank(writer); vm.expectRevert(); registry.anchorAudit(keccak256("b"), keccak256("c"));
    }
}
