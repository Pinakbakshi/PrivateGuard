// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script} from "forge-std/Script.sol";
import {PrivacyAuditRegistry} from "../src/PrivacyAuditRegistry.sol";

contract DeployPrivacyAuditRegistry is Script {
    function run() external returns (PrivacyAuditRegistry registry) {
        uint256 deployerKey = vm.envUint("PRIVATEGUARD_DEPLOYER_PRIVATE_KEY");
        address admin = vm.envAddress("PRIVATEGUARD_REGISTRY_ADMIN");
        vm.startBroadcast(deployerKey);
        registry = new PrivacyAuditRegistry(admin);
        vm.stopBroadcast();
    }
}
