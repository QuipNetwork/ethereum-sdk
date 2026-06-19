// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {Script, console} from "forge-std-1.14.0/Script.sol";
import {ICreateX} from "pcaversaccio-createx-1.0.0/src/ICreateX.sol";
import {Deployer} from "../contracts/Deployer.sol";

/**
 * @title DeployDeployer
 * @dev Bootstraps the `Deployer` contract on a fresh chain via pcaversaccio's
 *      canonical CreateX factory at `0xba5Ed099633D3B313e4D5F7bdc1305d3c28ba5Ed`.
 *
 *      The Deployer is the only contract Quip deploys that can't itself use
 *      CREATE3 (solady's `CREATE3` library is `internal`, so it needs *some*
 *      already-on-chain contract to call it from). CreateX solves this by
 *      being itself a singleton, pre-deployed at the same address on every
 *      EVM chain via Nick's-method presigned tx.
 *
 *      Salt:  `keccak256("QUIP:Deployer:V1")`.
 *             The first 20 bytes of this hash are neither `msg.sender` nor
 *             `address(0)`, so CreateX's `_guard` hits its "other" branch
 *             which produces `guardedSalt = keccak256(salt)`. This mode is:
 *               - *unguarded*: anyone with funds on a fresh chain can run
 *                 this script and the Deployer will land at the right
 *                 address (no operator pinning, no nonce ritual, no fresh
 *                 wallet required).
 *               - *cross-chain identical*: CreateX is at the same address
 *                 on every chain, and the guarded salt is identical, so the
 *                 resulting Deployer address is identical.
 *
 *      Front-run consideration: `Deployer.deploy()` is already public (it
 *      has been since v0), so the threat model doesn't change. An attacker
 *      could in principle bootstrap the Deployer for us; that would just
 *      give us a working Deployer at the correct address for free.
 *
 * Usage:
 *   forge script script/DeployDeployer.s.sol --rpc-url $RPC --private-key $PRIVATE_KEY --broadcast --verify
 *
 *   To dry-run prediction without broadcasting:
 *     forge script script/DeployDeployer.s.sol
 *
 * Environment:
 *   PRIVATE_KEY - Any funded wallet on the target chain (no nonce constraint).
 *                 Pays gas for the CreateX call; doesn't appear in the
 *                 resulting Deployer's address derivation.
 */
contract DeployDeployer is Script {
    /// @dev Canonical CreateX factory address. Same on every chain.
    address internal constant CREATEX = 0xba5Ed099633D3B313e4D5F7bdc1305d3c28ba5Ed;

    /// @dev Raw salt for the Deployer's CREATE3 deploy. CreateX wraps this
    ///      to `keccak256(abi.encode(salt))` before computing the address.
    bytes32 internal constant DEPLOYER_SALT = keccak256("QUIP:Deployer:V1");

    function run() external {
        require(CREATEX.code.length > 0, "CreateX not deployed on this chain");

        bytes32 guardedSalt = keccak256(abi.encode(DEPLOYER_SALT));
        address expectedAddr = ICreateX(CREATEX).computeCreate3Address(guardedSalt);

        console.log("CreateX:           ", CREATEX);
        console.log("Expected Deployer: ", expectedAddr);

        if (expectedAddr.code.length > 0) {
            console.log("\nDeployer already deployed. Skipping.");
            return;
        }

        uint256 privateKey = vm.envUint("PRIVATE_KEY");

        vm.startBroadcast(privateKey);
        address deployed = ICreateX(CREATEX).deployCreate3(DEPLOYER_SALT, type(Deployer).creationCode);
        vm.stopBroadcast();

        require(deployed == expectedAddr, "Deployer address mismatch");
        console.log("\nDeployer deployed at:", deployed);
        console.log("\nNext steps:");
        console.log("  1. Update src/v1/addresses.json Deployer to:", deployed);
        console.log("  2. Run `make predict-addresses` to see the predicted downstream addresses.");
        console.log("  3. Run `make deploy-all-<chain>` to deploy WOTSPlus + Factory + Paymaster.");
    }
}
