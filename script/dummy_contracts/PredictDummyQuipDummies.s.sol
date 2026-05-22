// SPDX-License-Identifier: MIT
pragma solidity ^0.8.33;

import {Script, console} from "forge-std-1.14.0/Script.sol";
import {DummyQuipCreate3Factory} from "../../contracts/dummy_contracts/DummyQuipCreate3Factory.sol";
import {DummyQuipDeploymentConfig as Config} from "./DummyQuipDeploymentConfig.sol";

contract PredictDummyQuipDummies is Script {
    function run() external view {
        address factoryAddress = vm.envAddress("DUMMY_QUIP_CREATE3_FACTORY");
        DummyQuipCreate3Factory factory = DummyQuipCreate3Factory(factoryAddress);

        require(factoryAddress.code.length != 0, "DUMMY_QUIP_CREATE3_FACTORY has no code on this chain");

        console.log("DUMMY_QUIP_CREATE3_FACTORY:", factoryAddress);
        _print(factory, "DummyQuipERC20SixDecimals", Config.saltERC20SixDecimals());
        _print(factory, "DummyQuipERC20EighteenDecimals", Config.saltERC20EighteenDecimals());
        _print(factory, "DummyQuipERC20Spender", Config.saltERC20Spender());
        _print(factory, "DummyQuipPaymentReceiver", Config.saltPaymentReceiver());
        _print(factory, "DummyQuipNonPayableReceiver", Config.saltNonPayableReceiver());
        _print(factory, "DummyQuipRevertingReceiver", Config.saltRevertingReceiver());
    }

    function _print(DummyQuipCreate3Factory factory, string memory label, bytes32 salt) internal view {
        address predicted = factory.getDeployed(salt);
        console.log(label, predicted);
    }
}
