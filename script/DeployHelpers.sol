// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {Script, console} from "forge-std-1.14.0/Script.sol";

/// Minimal WalletFactory surface used by the deploy orchestrators — kept as a local
/// interface so this generic helper carries no WOTSPlus-linked dependency.
interface IVettingFactory {
    function vetImplementation(address impl) external;
    function getVettedCodeIndex(bytes32 codehash) external view returns (uint256);
    function owner() external view returns (address);
    function latestWalletImpl() external view returns (address);
}

/**
 * @title DeployHelpers
 * @dev Generic vetting/existence primitives shared by every deploy orchestrator.
 *      Carries no concrete contract `creationCode` references and no deploy
 *      mechanism: live contracts deploy via `CreateXHelpers` (sender-guarded
 *      CreateX CREATE3); the sunset WOTS+ family via
 *      `script/deprecated/DeployerCreate3.sol`.
 *
 *      Every helper is idempotent: an already-vetted implementation is not
 *      re-vetted (which would revert `AlreadyVetted`). Re-running any orchestrator
 *      is therefore safe.
 */
abstract contract DeployHelpers is Script {
    /// `type(uint256).max` is `getVettedCodeIndex`'s "not vetted" sentinel.
    uint256 internal constant NOT_VETTED = type(uint256).max;

    function _requireExists(address target, string memory name) internal view {
        require(target.code.length > 0, string.concat(name, " not deployed"));
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
