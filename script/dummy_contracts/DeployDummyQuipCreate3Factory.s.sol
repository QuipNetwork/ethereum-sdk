// SPDX-License-Identifier: MIT
pragma solidity ^0.8.33;

import {Script, console} from "forge-std-1.14.0/Script.sol";
import {DummyQuipCreate3Factory} from "../../contracts/dummy_contracts/DummyQuipCreate3Factory.sol";

contract DeployDummyQuipCreate3Factory is Script {
    function run() external returns (DummyQuipCreate3Factory factory) {
        uint256 privateKey = vm.envUint("PRIVATE_KEY");

        vm.startBroadcast(privateKey);
        factory = new DummyQuipCreate3Factory();
        vm.stopBroadcast();

        console.log("DummyQuipCreate3Factory:", address(factory));
        console.log("Set this in .env as DUMMY_QUIP_CREATE3_FACTORY=<address above>");
    }
}
