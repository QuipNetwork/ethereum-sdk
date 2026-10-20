// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {LibClone} from "solady-0.1.26/src/utils/LibClone.sol";
import {WalletFactoryTest} from "../WalletFactory.t.sol";
import {WalletFactoryHarness} from "../../harness/WalletFactoryHarness.sol";
import {WOTSPlusImplementation} from "../../../contracts/deprecated/wots/WOTSPlusImplementation.sol";

contract WalletFactory__findLatestActive is WalletFactoryTest {
    WalletFactoryHarness public harness;

    function setUp() public override {
        super.setUp();
        WalletFactoryHarness harnessImpl = new WalletFactoryHarness(0.1 ether);
        harness = WalletFactoryHarness(payable(LibClone.deployERC1967(address(harnessImpl))));
        harness.initialize(payable(ADMIN));
    }

    /// @dev Vets `n` fresh implementations (in index order) and returns them. Each test then
    ///      deprecates a distinct subset — the deprecation PATTERN is the property under test.
    function _vetImpls(uint256 n) internal returns (WOTSPlusImplementation[] memory impls) {
        impls = new WOTSPlusImplementation[](n);
        vm.startPrank(ADMIN);
        for (uint256 i = 0; i < n; i++) {
            impls[i] = new WOTSPlusImplementation(payable(address(harness)));
            harness.vetImplementation(address(impls[i]));
        }
        vm.stopPrank();
    }

    function _deprecate(WOTSPlusImplementation impl) internal {
        vm.prank(ADMIN);
        harness.deprecateImplementation(address(impl));
    }

    function test_exposed_findLatestActive_returnsZeroWhenEmpty() public view {
        assertEq(harness.exposed_findLatestActive(), address(0));
    }

    // Pattern: [active, active, active]. The pure happy path returns the last entry.
    function test_exposed_findLatestActive_returnsLatestVetted() public {
        WOTSPlusImplementation[] memory impls = _vetImpls(3);
        assertEq(harness.exposed_findLatestActive(), address(impls[2]));
    }

    // Pattern: [active, active, deprecated]. A single trailing deprecated entry is skipped.
    // Kept alongside `skipsMultipleDeprecated`: a double-decrement loop mutant passes the
    // two-skip case but lands on the wrong entry here.
    function test_exposed_findLatestActive_skipsDeprecated() public {
        WOTSPlusImplementation[] memory impls = _vetImpls(3);
        _deprecate(impls[2]);
        assertEq(harness.exposed_findLatestActive(), address(impls[1]));
    }

    function test_exposed_findLatestActive_returnsZeroWhenAllDeprecated() public {
        WOTSPlusImplementation[] memory impls = _vetImpls(1);
        _deprecate(impls[0]);
        assertEq(harness.exposed_findLatestActive(), address(0));
    }

    function test_exposed_findLatestActive_returnsUndeprecatedImpl() public {
        WOTSPlusImplementation[] memory impls = _vetImpls(1);
        _deprecate(impls[0]);
        vm.prank(ADMIN);
        harness.undeprecateImplementation(address(impls[0]));
        assertEq(harness.exposed_findLatestActive(), address(impls[0]));
    }

    // Pattern: [active, deprecated, deprecated]. The backward scan must walk
    // past *two* consecutive deprecated entries before returning the active
    // one at index 0 — pins the loop-continues invariant when the latest N
    // entries are all deprecated.
    function test_exposed_findLatestActive_skipsMultipleDeprecated() public {
        WOTSPlusImplementation[] memory impls = _vetImpls(3);
        _deprecate(impls[2]);
        _deprecate(impls[1]);
        assertEq(harness.exposed_findLatestActive(), address(impls[0]));
    }

    // Pattern: [active, deprecated, active]. Backward scan returns the rightmost
    // active entry without examining earlier entries — guards against a bug
    // where the loop over-shoots the first active hit.
    function test_exposed_findLatestActive_returnsFirstActiveFromRight() public {
        WOTSPlusImplementation[] memory impls = _vetImpls(3);
        _deprecate(impls[1]);
        assertEq(harness.exposed_findLatestActive(), address(impls[2]));
    }
}
