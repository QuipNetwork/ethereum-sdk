// SPDX-License-Identifier: MIT
pragma solidity ^0.8.33;

import {Script, console} from "forge-std-1.14.0/Script.sol";
import {DummyQuipCreate3Factory} from "../../contracts/dummy_contracts/DummyQuipCreate3Factory.sol";
import {DummyQuipDeploymentConfig as Config} from "./DummyQuipDeploymentConfig.sol";

contract DeployDummyQuipDummies is Script {
    struct DummyQuipDummyAddresses {
        address dummyQuipERC20SixDecimals;
        address dummyQuipERC20EighteenDecimals;
        address dummyQuipERC20Spender;
        address dummyQuipPaymentReceiver;
        address dummyQuipNonPayableReceiver;
        address dummyQuipRevertingReceiver;
    }

    function run() external returns (DummyQuipDummyAddresses memory deployed) {
        uint256 privateKey = vm.envUint("PRIVATE_KEY");
        address defaultOwner = vm.addr(privateKey);
        address owner = vm.envOr("DUMMY_QUIP_OWNER", defaultOwner);
        address factoryAddress = vm.envAddress("DUMMY_QUIP_CREATE3_FACTORY");
        DummyQuipCreate3Factory factory = DummyQuipCreate3Factory(factoryAddress);

        require(factoryAddress.code.length != 0, "DUMMY_QUIP_CREATE3_FACTORY has no code on this chain");

        console.log("DUMMY_QUIP_CREATE3_FACTORY:", factoryAddress);
        console.log("DUMMY_QUIP_OWNER:", owner);

        vm.startBroadcast(privateKey);

        deployed.dummyQuipERC20SixDecimals = _deployIfNeeded(
            factory,
            "DummyQuipERC20SixDecimals",
            Config.saltERC20SixDecimals(),
            Config.codeERC20SixDecimals(owner)
        );

        deployed.dummyQuipERC20EighteenDecimals = _deployIfNeeded(
            factory,
            "DummyQuipERC20EighteenDecimals",
            Config.saltERC20EighteenDecimals(),
            Config.codeERC20EighteenDecimals(owner)
        );

        deployed.dummyQuipERC20Spender = _deployIfNeeded(
            factory,
            "DummyQuipERC20Spender",
            Config.saltERC20Spender(),
            Config.codeERC20Spender()
        );

        deployed.dummyQuipPaymentReceiver = _deployIfNeeded(
            factory,
            "DummyQuipPaymentReceiver",
            Config.saltPaymentReceiver(),
            Config.codePaymentReceiver(owner)
        );

        deployed.dummyQuipNonPayableReceiver = _deployIfNeeded(
            factory,
            "DummyQuipNonPayableReceiver",
            Config.saltNonPayableReceiver(),
            Config.codeNonPayableReceiver()
        );

        deployed.dummyQuipRevertingReceiver = _deployIfNeeded(
            factory,
            "DummyQuipRevertingReceiver",
            Config.saltRevertingReceiver(),
            Config.codeRevertingReceiver()
        );

        vm.stopBroadcast();

        console.log("--- DummyQuip dummy deployment complete ---");
        console.log("DummyQuipERC20SixDecimals:", deployed.dummyQuipERC20SixDecimals);
        console.log("DummyQuipERC20EighteenDecimals:", deployed.dummyQuipERC20EighteenDecimals);
        console.log("DummyQuipERC20Spender:", deployed.dummyQuipERC20Spender);
        console.log("DummyQuipPaymentReceiver:", deployed.dummyQuipPaymentReceiver);
        console.log("DummyQuipNonPayableReceiver:", deployed.dummyQuipNonPayableReceiver);
        console.log("DummyQuipRevertingReceiver:", deployed.dummyQuipRevertingReceiver);
    }

    function _deployIfNeeded(
        DummyQuipCreate3Factory factory,
        string memory label,
        bytes32 salt,
        bytes memory creationCode
    ) internal returns (address predicted) {
        predicted = factory.getDeployed(salt);
        if (predicted.code.length == 0) {
            address addr = factory.deploy(salt, creationCode, 0);
            require(addr == predicted, "CREATE3 deployed address mismatch");
            console.log(label, addr);
        } else {
            console.log(label, predicted);
            console.log("  already deployed; skipping");
        }
    }
}
