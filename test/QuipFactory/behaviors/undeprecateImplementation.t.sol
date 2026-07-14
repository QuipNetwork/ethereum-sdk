// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {QuipFactoryTest} from "../QuipFactory.t.sol";
import {WOTSPlusImplementation} from "../../../contracts/wots/WOTSPlusImplementation.sol";
import {IQuipFactory} from "../../../contracts/interfaces/IQuipFactory.sol";
import {Ownable} from "solady-0.1.26/src/auth/Ownable.sol";
import {Vm} from "forge-std-1.14.0/Vm.sol";

/// @title undeprecateImplementation Tests
/// @dev Behavioral coverage for the dedicated reactivation entry point. Splitting
///      vet (fresh-add) and undeprecate (reactivate) into separate operations
///      makes the lifecycle reconstructable from events alone and gives each its
///      own latest-pointer update rule. The interesting case the prior in-place
///      `vetImplementation` re-vet missed: undeprecating the highest-index
///      entry must restore it as `latestWalletImpl`.
contract QuipFactory_undeprecateImplementation is QuipFactoryTest {
    // ── Happy paths ──────────────────────────────────────────────────

    function test_undeprecateImplementation_clearsDeprecatedFlag() public {
        bytes32 codehash = address(walletImplementation).codehash;
        vm.prank(ADMIN);
        factory.deprecateImplementation(address(walletImplementation));
        assertTrue(factory.deprecatedImpls(codehash));

        vm.prank(ADMIN);
        factory.undeprecateImplementation(address(walletImplementation));
        assertFalse(factory.deprecatedImpls(codehash));
    }

    /// @dev When the only impl is reactivated and `latestWalletImpl` is
    ///      currently zero, undeprecate restores it.
    function test_undeprecateImplementation_restoresLatestWhenNoneActive() public {
        vm.prank(ADMIN);
        factory.deprecateImplementation(address(walletImplementation));
        assertEq(factory.latestWalletImpl(), address(0));

        vm.prank(ADMIN);
        factory.undeprecateImplementation(address(walletImplementation));
        assertEq(factory.latestWalletImpl(), address(walletImplementation));
    }

    /// @dev The bug the in-place `vetImplementation` re-vet missed: deprecate
    ///      the highest-index entry, then undeprecate it. `latestWalletImpl`
    ///      must restore to that entry, not stay at the lower-index fallback.
    function test_undeprecateImplementation_restoresLatestForLastIndexEntry() public {
        WOTSPlusImplementation impl2 = new WOTSPlusImplementation(payable(address(factory)));
        vm.prank(ADMIN);
        factory.vetImplementation(address(impl2));
        // Set is now [walletImplementation, impl2]; latest = impl2.

        vm.prank(ADMIN);
        factory.deprecateImplementation(address(impl2));
        assertEq(factory.latestWalletImpl(), address(walletImplementation));

        vm.prank(ADMIN);
        factory.undeprecateImplementation(address(impl2));
        assertEq(factory.latestWalletImpl(), address(impl2));
    }

    /// @dev Mirror of the original `reVetDoesNotChangeLatestWhenOneActive`
    ///      coverage: undeprecating a lower-index entry must NOT displace the
    ///      higher-index entry that is already the latest.
    function test_undeprecateImplementation_doesNotChangeLatestForMiddleIndexEntry() public {
        WOTSPlusImplementation impl2 = new WOTSPlusImplementation(payable(address(factory)));
        vm.prank(ADMIN);
        factory.vetImplementation(address(impl2));
        // Set is now [walletImplementation, impl2]; latest = impl2.

        vm.prank(ADMIN);
        factory.deprecateImplementation(address(walletImplementation));
        assertEq(factory.latestWalletImpl(), address(impl2));

        vm.prank(ADMIN);
        factory.undeprecateImplementation(address(walletImplementation));
        assertEq(factory.latestWalletImpl(), address(impl2));
    }

    /// @dev Address re-bind: a redeploy of identical bytecode at a different
    ///      address (e.g. CREATE2/CREATE3 with a different salt on another
    ///      chain) can replace the address pointer for the same codehash.
    ///      Same code = same behavior, so the security boundary (codehash) is
    ///      unchanged. We use `vm.etch` to copy the runtime bytecode to a
    ///      fresh address — `EXTCODEHASH` is `keccak256(runtime_code)`, so
    ///      identical bytes at a different address yield the same codehash by
    ///      definition.
    function test_undeprecateImplementation_rebindsAddressForSameCodehash() public {
        bytes32 codehash = address(walletImplementation).codehash;

        vm.prank(ADMIN);
        factory.deprecateImplementation(address(walletImplementation));

        address redeploy = makeAddr("same-code-redeploy");
        vm.etch(redeploy, address(walletImplementation).code);
        assertEq(redeploy.codehash, codehash);
        assertTrue(redeploy != address(walletImplementation));

        vm.prank(ADMIN);
        factory.undeprecateImplementation(redeploy);

        assertEq(factory.vettedWalletImpls(codehash), redeploy);
    }

    function test_undeprecateImplementation_emitsImplementationUndeprecated() public {
        bytes32 codehash = address(walletImplementation).codehash;
        vm.prank(ADMIN);
        factory.deprecateImplementation(address(walletImplementation));

        vm.prank(ADMIN);
        vm.recordLogs();
        factory.undeprecateImplementation(address(walletImplementation));

        Vm.Log[] memory logs = vm.getRecordedLogs();
        bool found = false;
        for (uint256 i = 0; i < logs.length; i++) {
            if (logs[i].topics[0] == IQuipFactory.ImplementationUndeprecated.selector) {
                assertEq(logs[i].topics[1], bytes32(uint256(uint160(address(walletImplementation)))));
                // codehash is now indexed → topics[2].
                assertEq(logs[i].topics[2], codehash);
                found = true;
                break;
            }
        }
        assertTrue(found, "ImplementationUndeprecated event not emitted");
    }

    // ── Reverts ──────────────────────────────────────────────────────

    function test_undeprecateImplementation_revertsWhen_notVetted() public {
        // `address(this)` has the test contract's codehash, which has never
        // been vetted — distinct from walletImplementation's codehash.
        vm.prank(ADMIN);
        vm.expectRevert(IQuipFactory.ImplementationNotVetted.selector);
        factory.undeprecateImplementation(address(this));
    }

    function test_undeprecateImplementation_revertsWhen_notDeprecated() public {
        // walletImplementation is vetted-and-active by setUp.
        vm.prank(ADMIN);
        vm.expectRevert(IQuipFactory.NotDeprecated.selector);
        factory.undeprecateImplementation(address(walletImplementation));
    }

    function test_undeprecateImplementation_revertsWhen_callerNotOwner() public {
        vm.prank(ADMIN);
        factory.deprecateImplementation(address(walletImplementation));

        vm.prank(ALICE);
        vm.expectRevert(Ownable.Unauthorized.selector);
        factory.undeprecateImplementation(address(walletImplementation));
    }
}
