// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {SHRINCS} from "@quip.network/hashsigs-solidity-0.2.0/contracts/SHRINCS.sol";
import {ShrincsWalletCodec as Codec} from "../../../contracts/shrincs/ShrincsWalletCodec.sol";
import {ShrincsWalletHarness} from "../../harness/ShrincsWalletHarness.sol";
import {ShrincsWalletTest} from "../ShrincsWallet.t.sol";

/// @dev Unit tests for `_msgImplementation` (via `exposed_msgImplementation`), the wallet's own
///      ERC-1967 pointer read — the STORAGE fact `version()` and `_enforceUpgradeInFlight` key
///      off. On a live proxy it is the installed implementation; on a bare implementation the
///      slot is empty; after a real upgrade it follows the swap.
contract ShrincsWallet__msgImplementation is ShrincsWalletTest {
    /// @dev Real signed no-migrate upgrade of the base wallet to `impl`.
    function _upgradeTo(address impl) internal {
        vm.prank(ADMIN);
        factory.vetImplementation(impl);
        SHRINCS.Signature memory sig = _signStatefulAction(
            Codec.ACTION_UPGRADE, Codec.upgradePayloadHash(impl, false, keccak256(bytes(""))), 1
        );
        bytes memory data =
            abi.encode(_mainPk(), sig, false, bytes(""), wallet.actionNonce(), _probeVectorFor(impl));
        vm.prank(OWNER);
        wallet.upgradeToAndCall(impl, data);
    }

    function test_exposed_msgImplementation_readsInstalledImplementation() public view {
        assertEq(
            wallet.exposed_msgImplementation(),
            address(walletImplementation),
            "live proxy reports its installed implementation"
        );
    }

    function test_exposed_msgImplementation_zeroOnBareImplementation() public {
        ShrincsWalletHarness bare =
            new ShrincsWalletHarness(payable(address(factory)), address(shrincsVerifier));
        assertEq(bare.exposed_msgImplementation(), address(0), "bare implementation has no pointer");
    }

    function test_exposed_msgImplementation_followsUpgrade() public {
        ShrincsWalletHarness next =
            new ShrincsWalletHarness(payable(address(factory)), address(shrincsVerifier));
        _upgradeTo(address(next));
        assertEq(
            wallet.exposed_msgImplementation(), address(next), "pointer follows the ERC-1967 swap"
        );
    }
}
