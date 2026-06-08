// SPDX-License-Identifier: MIT
pragma solidity ^0.8.33;

import {Script, console} from "forge-std-1.14.0/Script.sol";
import {DummyQuipCreate3Factory} from "../../contracts/dummy_contracts/DummyQuipCreate3Factory.sol";
import {DummyQuipDeploymentConfig as Config} from "./DummyQuipDeploymentConfig.sol";

/// @notice Prints the CREATE3 predicted addresses for the active DummyQuip token suite.
contract PredictDummyQuipDummies is Script {
    function run() external view {
        address factoryAddress = vm.envAddress("DUMMY_QUIP_CREATE3_FACTORY");
        DummyQuipCreate3Factory factory = DummyQuipCreate3Factory(factoryAddress);

        require(
            factoryAddress.code.length != 0,
            "DUMMY_QUIP_CREATE3_FACTORY has no code on this chain"
        );

        console.log("DUMMY_QUIP_CREATE3_FACTORY:", factoryAddress);
        _print(factory, "DummyQuipERC20SixDecimals", Config.saltERC20SixDecimals());
        _print(factory, "DummyQuipERC20EighteenDecimals", Config.saltERC20EighteenDecimals());
        _print(factory, "DummyQuipERC721", Config.saltERC721());
        _print(factory, "DummyQuipERC1155", Config.saltERC1155());
        _print(factory, "DummyQuipArbitraryCall", Config.saltArbitraryCall());
    }

    function _print(DummyQuipCreate3Factory factory, string memory label, bytes32 salt)
        internal
        view
    {
        address predicted = factory.getDeployed(salt);
        console.log(label, predicted);
    }
}
