// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {QuipWallet} from "../../contracts/QuipWallet.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.1.0/contracts/WOTSPlus.sol";

contract QuipWalletHarness is QuipWallet {
    constructor(address payable factory_) QuipWallet(factory_) {}

    function exposed_enforceNonZeroPqOwner(
        WOTSPlus.WinternitzAddress calldata pqOwner
    ) external pure {
        _enforceNonZeroPqOwner(pqOwner);
    }

    function exposed_enforceDifferentPqOwner(
        WOTSPlus.WinternitzAddress calldata nextPqOwner
    ) external view {
        _enforceDifferentPqOwner(nextPqOwner);
    }

    function exposed_addRecoveryKeys(
        WOTSPlus.WinternitzAddress[] calldata keys
    ) external {
        _addRecoveryKeys(keys);
    }

    function exposed_addRecoveryKeysFixed(
        WOTSPlus.WinternitzAddress[10] calldata keys
    ) external {
        _addRecoveryKeys(keys);
    }

    function exposed_verifyInitialState() external view {
        _verifyInitialState();
    }

    function exposed_guardInitializeOwner() external pure returns (bool) {
        return _guardInitializeOwner();
    }

    function exposed_authorizeUpgrade(address newImpl) external {
        _authorizeUpgrade(newImpl);
    }

    function exposed_upgradeGuard() external view returns (uint256) {
        return _upgradeGuard();
    }
}
