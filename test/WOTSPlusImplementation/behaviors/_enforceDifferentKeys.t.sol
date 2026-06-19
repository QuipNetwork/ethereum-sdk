// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {WOTSPlusImplementationTest} from "../WOTSPlusImplementation.t.sol";
import {WOTSPlusImplementationHarness} from "../../harness/WOTSPlusImplementationHarness.sol";
import {IWOTSPlusImplementation} from "../../../contracts/wots/interfaces/IWOTSPlusImplementation.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.1.0/contracts/WOTSPlus.sol";

/// @dev Unit tests for `_enforceDifferentKeys(a, b)`. Reverts `SameKey` only
///      when both fields match exactly; differing in either field passes.
contract WOTSPlusImplementation__enforceDifferentKeys is WOTSPlusImplementationTest {
    WOTSPlusImplementationHarness public bare;

    function setUp() public override {
        super.setUp();
        bare = new WOTSPlusImplementationHarness(payable(address(factory)));
    }

    function _key(bytes32 seed, bytes32 hash) internal pure returns (WOTSPlus.WinternitzAddress memory) {
        return WOTSPlus.WinternitzAddress({publicSeed: seed, publicKeyHash: hash});
    }

    function test_exposed_enforceDifferentKeys_passes_whenSeedDiffers() public view {
        bare.exposed_enforceDifferentKeys(
            _key(bytes32(uint256(1)), bytes32(uint256(100))), _key(bytes32(uint256(2)), bytes32(uint256(100)))
        );
    }

    function test_exposed_enforceDifferentKeys_passes_whenHashDiffers() public view {
        bare.exposed_enforceDifferentKeys(
            _key(bytes32(uint256(1)), bytes32(uint256(100))), _key(bytes32(uint256(1)), bytes32(uint256(200)))
        );
    }

    function test_exposed_enforceDifferentKeys_passes_whenBothDiffer() public view {
        bare.exposed_enforceDifferentKeys(
            _key(bytes32(uint256(1)), bytes32(uint256(100))), _key(bytes32(uint256(2)), bytes32(uint256(200)))
        );
    }

    // Two zero-valued keys ARE the same key by field equality. The helper has
    // no zero-short-circuit (unlike `_isKeyInUse`); it strictly tests pairwise
    // equality. Zero-key inputs are caught later by the keyset library; this
    // test pins down the helper's narrow contract.
    function test_exposed_enforceDifferentKeys_revertsWhen_bothZero() public {
        WOTSPlus.WinternitzAddress memory zero;
        vm.expectRevert(IWOTSPlusImplementation.SameKey.selector);
        bare.exposed_enforceDifferentKeys(zero, zero);
    }

    function test_exposed_enforceDifferentKeys_revertsWhen_keysIdentical() public {
        WOTSPlus.WinternitzAddress memory k = _key(bytes32(uint256(0xaa)), bytes32(uint256(0xbb)));
        vm.expectRevert(IWOTSPlusImplementation.SameKey.selector);
        bare.exposed_enforceDifferentKeys(k, k);
    }
}
