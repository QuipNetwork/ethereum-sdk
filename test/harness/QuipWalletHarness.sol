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

    function exposed_rotatePqOwner(WOTSPlus.WinternitzAddress calldata nextPqOwner) external {
        _rotatePqOwner(nextPqOwner);
    }

    function exposed_upgradeGuardInContext() external returns (uint256) {
        // _UPGRADE_GUARD_SLOT is private; replicate the constant
        uint256 slot = 0x490d87f9a8524f6238d75626265800824e3fa88e60bc82c13f11bbd9042ed677;
        assembly { tstore(slot, 1) }
        uint256 v = _upgradeGuard();
        assembly { tstore(slot, 0) }
        return v;
    }
}
