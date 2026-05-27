// SPDX-License-Identifier: MIT
pragma solidity ^0.8.33;

import {Script, console} from "forge-std-1.14.0/Script.sol";
import {DummyQuipCreate3Factory} from "../../contracts/dummy_contracts/DummyQuipCreate3Factory.sol";
import {DummyQuipDeploymentConfig as Config} from "./DummyQuipDeploymentConfig.sol";

/// @notice Deploys ONLY the two DummyQuipERC20 variants (tQ6, tQ18) via the pre-deployed
///         DummyQuipCreate3Factory. Use `DeployDummyQuipDummies.s.sol` for the full suite.
contract DeployDummyQuipERC20s is Script {
    struct DummyQuipERC20Addresses {
        address dummyQuipERC20SixDecimals;
        address dummyQuipERC20EighteenDecimals;
    }

    function run() external returns (DummyQuipERC20Addresses memory deployed) {
        uint256 privateKey = vm.envUint("PRIVATE_KEY");
        address factoryAddress = vm.envAddress("DUMMY_QUIP_CREATE3_FACTORY");
        DummyQuipCreate3Factory factory = DummyQuipCreate3Factory(factoryAddress);

        require(
            factoryAddress.code.length != 0,
            "DUMMY_QUIP_CREATE3_FACTORY has no code on this chain"
        );

        console.log("DUMMY_QUIP_CREATE3_FACTORY:", factoryAddress);

        vm.startBroadcast(privateKey);

        deployed.dummyQuipERC20SixDecimals = _deployIfNeeded(
            factory,
            "DummyQuipERC20SixDecimals",
            Config.saltERC20SixDecimals(),
            Config.codeERC20SixDecimals()
        );

        deployed.dummyQuipERC20EighteenDecimals = _deployIfNeeded(
            factory,
            "DummyQuipERC20EighteenDecimals",
            Config.saltERC20EighteenDecimals(),
            Config.codeERC20EighteenDecimals()
        );

        vm.stopBroadcast();

        console.log("--- DummyQuipERC20 deployment complete ---");
        console.log("DummyQuipERC20SixDecimals:", deployed.dummyQuipERC20SixDecimals);
        console.log("DummyQuipERC20EighteenDecimals:", deployed.dummyQuipERC20EighteenDecimals);
    }

    function _deployIfNeeded(
        DummyQuipCreate3Factory factory,
        string memory label,
        bytes32 salt,
        bytes memory creationCode
    ) internal returns (address predicted) {
        predicted = factory.getDeployed(salt);
        if (predicted.code.length == 0) {
            address addr = factory.deploy(salt, creationCode);
            require(addr == predicted, "CREATE3 deployed address mismatch");
            console.log(label, addr);
        } else {
            console.log(label, predicted);
            console.log("  already deployed; skipping");
        }
    }
}
