// SPDX-License-Identifier: MIT
pragma solidity ^0.8.33;

import {Script, console} from "forge-std-1.14.0/Script.sol";
import {DummyQuipCreate3Factory} from "../../contracts/dummy_contracts/DummyQuipCreate3Factory.sol";
import {DummyQuipDeploymentConfig as Config} from "./DummyQuipDeploymentConfig.sol";

/// @notice Deploys the active DummyQuip token suite (ERC20 ×2, ERC721, ERC1155) via the
///         pre-deployed DummyQuipCreate3Factory.
contract DeployDummyQuipDummies is Script {
    struct DummyQuipDummyAddresses {
        address dummyQuipERC20SixDecimals;
        address dummyQuipERC20EighteenDecimals;
        address dummyQuipERC721;
        address dummyQuipERC1155;
        address dummyQuipArbitraryCall;
    }

    function run() external returns (DummyQuipDummyAddresses memory deployed) {
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

        deployed.dummyQuipERC721 = _deployIfNeeded(
            factory,
            "DummyQuipERC721",
            Config.saltERC721(),
            Config.codeERC721()
        );

        deployed.dummyQuipERC1155 = _deployIfNeeded(
            factory,
            "DummyQuipERC1155",
            Config.saltERC1155(),
            Config.codeERC1155()
        );

        deployed.dummyQuipArbitraryCall = _deployIfNeeded(
            factory,
            "DummyQuipArbitraryCall",
            Config.saltArbitraryCall(),
            Config.codeArbitraryCall()
        );

        vm.stopBroadcast();

        console.log("--- DummyQuip dummy deployment complete ---");
        console.log("DummyQuipERC20SixDecimals:", deployed.dummyQuipERC20SixDecimals);
        console.log("DummyQuipERC20EighteenDecimals:", deployed.dummyQuipERC20EighteenDecimals);
        console.log("DummyQuipERC721:", deployed.dummyQuipERC721);
        console.log("DummyQuipERC1155:", deployed.dummyQuipERC1155);
        console.log("DummyQuipArbitraryCall:", deployed.dummyQuipArbitraryCall);
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
