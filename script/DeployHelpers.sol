// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {Script, console} from "forge-std-1.14.0/Script.sol";
import {CREATE3} from "solady-0.1.26/src/utils/CREATE3.sol";
import {Deployer} from "../contracts/Deployer.sol";

/// Minimal QuipFactory surface used by the deploy orchestrators — kept as a local
/// interface so this generic helper carries no WOTSPlus-linked dependency.
interface IVettingFactory {
    function vetImplementation(address impl) external;
    function getVettedCodeIndex(bytes32 codehash) external view returns (uint256);
    function owner() external view returns (address);
    function latestWalletImpl() external view returns (address);
}

/**
 * @title DeployHelpers
 * @dev Generic, contract-agnostic CREATE3 deploy + vetting primitives shared by
 *      `DeployAllWots`, `DeployAllShrincs`, and `DeployAll`. Carries no concrete
 *      contract `creationCode` references, so inheritors that only deploy Shrincs
 *      need no WOTSPlus library linking.
 *
 *      Every helper is idempotent: a contract already present at its deterministic
 *      CREATE3 address is skipped, and an already-vetted implementation is not
 *      re-vetted (which would revert `AlreadyVetted`). Re-running any orchestrator
 *      is therefore safe.
 */
abstract contract DeployHelpers is Script {
    /// `type(uint256).max` is `getVettedCodeIndex`'s "not vetted" sentinel.
    uint256 internal constant NOT_VETTED = type(uint256).max;

    function _requireExists(address target, string memory name) internal view {
        require(target.code.length > 0, string.concat(name, " not deployed"));
    }

    /// Deploy `bytecode` at the deterministic `(deployer, salt)` CREATE3 address,
    /// skipping if already present. Reverts on an unexpected address.
    function _create3(
        Deployer deployer,
        uint256 privateKey,
        bytes memory bytecode,
        bytes32 salt,
        string memory name
    ) internal returns (address deployed) {
        address expected = CREATE3.predictDeterministicAddress(salt, address(deployer));
        if (expected.code.length > 0) {
            console.log(string.concat("  - ", name, " already at"), expected);
            return expected;
        }
        vm.startBroadcast(privateKey);
        deployed = deployer.deploy(bytecode, salt);
        vm.stopBroadcast();
        require(deployed == expected, string.concat(name, ": CREATE3 address mismatch"));
        console.log(string.concat("  - ", name, " deployed at"), deployed);
    }

    /// Vet `impl` on `factory` unless already vetted. NOTE: a successful vet sets
    /// the factory's `latestWalletImpl` to `impl` — orchestrators control vetting
    /// ORDER so `deployLatestWalletProxy` resolves to the intended default.
    function _vetIfNeeded(
        address factory,
        uint256 privateKey,
        address impl,
        string memory name
    ) internal {
        IVettingFactory f = IVettingFactory(factory);
        if (f.getVettedCodeIndex(impl.codehash) != NOT_VETTED) {
            console.log(string.concat("  - ", name, " already vetted:"), impl);
            return;
        }
        vm.startBroadcast(privateKey);
        f.vetImplementation(impl);
        vm.stopBroadcast();
        console.log(string.concat("  - ", name, " vetted:"), impl);
    }
}
