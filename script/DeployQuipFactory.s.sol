// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {Script, console} from "forge-std-1.14.0/Script.sol";
import {CREATE3} from "solady-0.1.26/src/utils/CREATE3.sol";
import {ERC1967Proxy} from "@openzeppelin-contracts-5.6.0-rc.1/proxy/ERC1967/ERC1967Proxy.sol";
import {Deployer} from "../contracts/Deployer.sol";
import {QuipFactory} from "../contracts/QuipFactory.sol";

/**
 * @title DeployQuipFactory
 * @dev Deploys the QuipFactory as implementation + ERC-1967 proxy via the
 *      Deployer contract using CREATE3 (solady's `CREATE3.deployDeterministic`).
 *      Addresses depend only on (Deployer address, salt) — same on every
 *      chain, independent of constructor args. Owner / maxFee differ per
 *      chain but the addresses don't.
 *
 *      The PROXY address is the permanent factory identity: wallets bake it
 *      in as an immutable and CREATE3 wallet addressing derives from it, so
 *      it survives implementation upgrades. V2 salts — the V1.1 salt belongs
 *      to the retired non-upgradeable factory (CREATE3 ignores initcode, so
 *      reusing it on a chain with an existing V1.1 deployment would silently
 *      skip and leave the old factory in place).
 *
 *      NOTE: since the WOTS+ decoupling the factory links NO libraries
 *      (the WOTSPlus dependency is gone), so this script no longer needs
 *      `FOUNDRY_PROFILE=deploy`. Running with it is still harmless — and
 *      required for the orchestrators that also deploy the wallet impl.
 *
 * Usage:
 *   forge script script/DeployQuipFactory.s.sol \
 *       --rpc-url $RPC --private-key $PRIVATE_KEY --broadcast --verify
 *
 * Environment:
 *   PRIVATE_KEY      - Operations wallet private key
 *   DEPLOYER_ADDRESS - Deployer contract address (bootstrapped via DeployDeployer)
 *   FACTORY_OWNER    - Initial owner of the factory (controls vetting, fees, upgrades)
 *   MAX_FEE          - Maximum wallet-creation fee in wei (e.g. 1000000000000000 = 0.001 ETH)
 */
contract DeployQuipFactory is Script {
    bytes32 internal constant IMPL_SALT = keccak256("QUIP:QuipFactory:Impl:V2");
    bytes32 internal constant PROXY_SALT = keccak256("QUIP:QuipFactory:Proxy:V2");

    function run() external {
        address deployerAddr = vm.envAddress("DEPLOYER_ADDRESS");
        uint256 privateKey = vm.envUint("PRIVATE_KEY");
        address factoryOwner = vm.envAddress("FACTORY_OWNER");
        uint256 maxFee = vm.envUint("MAX_FEE");

        require(deployerAddr.code.length > 0, "Deployer not deployed. Run DeployDeployer first.");
        require(factoryOwner != address(0), "FACTORY_OWNER must be non-zero");
        require(maxFee != 0, "MAX_FEE must be non-zero");

        address expectedImpl = CREATE3.predictDeterministicAddress(IMPL_SALT, deployerAddr);
        address expectedProxy = CREATE3.predictDeterministicAddress(PROXY_SALT, deployerAddr);
        console.log("Deployer:                    ", deployerAddr);
        console.log("Factory owner:               ", factoryOwner);
        console.log("Max fee:                     ", maxFee);
        console.log("Expected QuipFactory impl:   ", expectedImpl);
        console.log("Expected QuipFactory (proxy):", expectedProxy);

        if (expectedImpl.code.length == 0) {
            bytes memory implCode = abi.encodePacked(type(QuipFactory).creationCode, abi.encode(maxFee));
            vm.startBroadcast(privateKey);
            address impl = Deployer(deployerAddr).deploy(implCode, IMPL_SALT);
            vm.stopBroadcast();
            require(impl == expectedImpl, "QuipFactory impl address mismatch");
            console.log("QuipFactory impl deployed at:", impl);
        } else {
            console.log("QuipFactory impl already deployed. Skipping.");
        }

        if (expectedProxy.code.length == 0) {
            bytes memory initData = abi.encodeCall(QuipFactory.initialize, (payable(factoryOwner)));
            bytes memory proxyCode =
                abi.encodePacked(type(ERC1967Proxy).creationCode, abi.encode(expectedImpl, initData));
            vm.startBroadcast(privateKey);
            address proxy = Deployer(deployerAddr).deploy(proxyCode, PROXY_SALT);
            vm.stopBroadcast();
            require(proxy == expectedProxy, "QuipFactory proxy address mismatch");
            console.log("QuipFactory proxy deployed at:", proxy);
        } else {
            console.log("QuipFactory proxy already deployed. Skipping.");
        }

        require(QuipFactory(payable(expectedProxy)).owner() == factoryOwner, "Factory owner mismatch");
        require(QuipFactory(payable(expectedProxy)).MAX_FEE() == maxFee, "Factory MAX_FEE mismatch");
    }
}
