// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {Script, console} from "forge-std-1.14.0/Script.sol";
import {CREATE3} from "solady-0.1.26/src/utils/CREATE3.sol";
import {ERC1967Proxy} from "@openzeppelin-contracts-5.6.0-rc.1/proxy/ERC1967/ERC1967Proxy.sol";
import {Deployer} from "../../contracts/deprecated/Deployer.sol";
import {QuipPaymaster} from "../../contracts/deprecated/QuipPaymaster.sol";

/**
 * @title DeployPaymaster
 * @dev Deploys the QuipPaymaster as a UUPS proxy via the existing Deployer.
 *
 *      Two CREATE3 deploys:
 *        1. The implementation contract (bare QuipPaymaster). Its constructor
 *           calls `_disableInitializers()`, so the implementation itself is
 *           inert by design.
 *        2. An OpenZeppelin ERC1967Proxy whose constructor `delegatecall`s
 *           `initialize(PAYMASTER_OWNER)` on the implementation, atomically
 *           initializing the proxy at deploy time.
 *
 *      The proxy is the canonical paymaster address — operators deposit gas
 *      into it, the SDK references it via `addresses.json`, and future
 *      upgrades retarget the proxy via `upgradeToAndCall`.
 *
 *      Cross-chain note: CREATE3 makes the impl and proxy addresses depend
 *      only on (Deployer address, salt). They will land at the same address
 *      on every chain. The on-chain *state* (owner, deposits) will differ
 *      per chain depending on PAYMASTER_OWNER and runtime activity, but the
 *      address is invariant.
 *
 * Usage:
 *   forge script script/DeployPaymaster.s.sol --rpc-url $RPC --private-key $PRIVATE_KEY --broadcast
 *
 * Environment:
 *   PRIVATE_KEY      - Operations wallet private key (deploys via Deployer)
 *   DEPLOYER_ADDRESS - Deployer contract address (per-chain, bootstrapped via DeployDeployer)
 *   PAYMASTER_OWNER  - Initial owner of the paymaster proxy (independent of factory owner)
 */
contract DeployPaymaster is Script {
    bytes32 internal constant IMPL_SALT = keccak256("QUIP:QuipPaymaster:Impl:V1.1");
    bytes32 internal constant PROXY_SALT = keccak256("QUIP:QuipPaymaster:Proxy:V1.1");

    function run() external {
        uint256 privateKey = vm.envUint("PRIVATE_KEY");
        address deployerAddr = vm.envAddress("DEPLOYER_ADDRESS");
        address paymasterOwner = vm.envAddress("PAYMASTER_OWNER");

        require(deployerAddr.code.length > 0, "Deployer not deployed. Run DeployDeployer first.");
        require(paymasterOwner != address(0), "PAYMASTER_OWNER must be non-zero");

        Deployer deployer = Deployer(deployerAddr);

        address expectedImpl = CREATE3.predictDeterministicAddress(IMPL_SALT, deployerAddr);
        address expectedProxy = CREATE3.predictDeterministicAddress(PROXY_SALT, deployerAddr);

        console.log("=== QuipPaymaster Deployment ===");
        console.log("Deployer:           ", deployerAddr);
        console.log("Paymaster owner:    ", paymasterOwner);
        console.log("Expected impl:      ", expectedImpl);
        console.log("Expected proxy:     ", expectedProxy);

        // --- Step 1: Deploy implementation ---
        address impl;
        if (expectedImpl.code.length > 0) {
            console.log("\nImplementation already deployed. Skipping.");
            impl = expectedImpl;
        } else {
            console.log("\n--- Deploying implementation ---");
            bytes memory implBytecode = type(QuipPaymaster).creationCode;
            console.log("Bytecode size:", implBytecode.length, "bytes");

            vm.startBroadcast(privateKey);
            impl = deployer.deploy(implBytecode, IMPL_SALT);
            vm.stopBroadcast();

            console.log("Implementation deployed at:", impl);
            require(impl == expectedImpl, "Impl address mismatch");
        }

        // --- Step 2: Deploy + initialize proxy ---
        // ERC1967Proxy(implementation, data) runs `upgradeToAndCall(impl, data)`
        // in its constructor, which delegatecalls `data` against `impl`. With
        // `data = abi.encodeCall(initialize, (owner))`, the proxy is fully
        // initialized atomically with deploy.
        address proxy;
        if (expectedProxy.code.length > 0) {
            console.log("\nProxy already deployed. Skipping init.");
            proxy = expectedProxy;
            _assertOwner(proxy, paymasterOwner);
        } else {
            console.log("\n--- Deploying proxy ---");
            bytes memory initData = abi.encodeCall(QuipPaymaster.initialize, (paymasterOwner));
            bytes memory proxyBytecode = abi.encodePacked(type(ERC1967Proxy).creationCode, abi.encode(impl, initData));
            console.log("Proxy bytecode size:", proxyBytecode.length, "bytes");

            vm.startBroadcast(privateKey);
            proxy = deployer.deploy(proxyBytecode, PROXY_SALT);
            vm.stopBroadcast();

            console.log("Proxy deployed at:", proxy);
            require(proxy == expectedProxy, "Proxy address mismatch");
            _assertOwner(proxy, paymasterOwner);
        }

        // --- Summary ---
        console.log("\n=== Deployment Summary ===");
        console.log("Implementation:     ", impl);
        console.log("Proxy (canonical):  ", proxy);
        console.log("Owner:              ", paymasterOwner);
    }

    /// @dev Reads `owner()` off the deployed proxy and reverts if it doesn't
    ///      match the expected owner. Catches the (otherwise silent) failure
    ///      mode where the impl + proxy land at the predicted address but
    ///      initialization didn't run as expected.
    function _assertOwner(address proxy, address expected) internal view {
        address actual = QuipPaymaster(payable(proxy)).owner();
        require(actual == expected, "Paymaster owner mismatch");
        console.log("Verified owner():    ", actual);
    }
}
