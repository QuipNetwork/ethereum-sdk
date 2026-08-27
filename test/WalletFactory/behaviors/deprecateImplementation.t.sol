// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {WalletFactoryTest} from "../WalletFactory.t.sol";
import {WOTSPlusImplementation} from "../../../contracts/deprecated/wots/WOTSPlusImplementation.sol";
import {IWalletFactory} from "../../../contracts/interfaces/IWalletFactory.sol";
import {Ownable} from "solady-0.1.26/src/auth/Ownable.sol";
import {Vm} from "forge-std-1.14.0/Vm.sol";

contract WalletFactory_deprecateImplementation is WalletFactoryTest {
    // ── Happy paths ──────────────────────────────────────────────────

    function test_deprecateImplementation_marksDeprecated() public {
        vm.prank(ADMIN);
        factory.deprecateImplementation(address(walletImplementation));

        assertTrue(factory.deprecatedImpls(address(walletImplementation).codehash));
    }

    function test_deprecateImplementation_updatesLatestWalletImpl() public {
        // Vet a second implementation
        WOTSPlusImplementation impl2 = new WOTSPlusImplementation(payable(address(factory)));
        vm.prank(ADMIN);
        factory.vetImplementation(address(impl2));

        assertEq(factory.latestWalletImpl(), address(impl2));

        // Deprecate impl2 — should fall back to first impl
        vm.prank(ADMIN);
        factory.deprecateImplementation(address(impl2));

        assertEq(factory.latestWalletImpl(), address(walletImplementation));
    }

    function test_deprecateImplementation_emitsImplementationSunset() public {
        vm.prank(ADMIN);
        vm.recordLogs();
        factory.deprecateImplementation(address(walletImplementation));

        Vm.Log[] memory logs = vm.getRecordedLogs();
        bool found = false;
        for (uint256 i = 0; i < logs.length; i++) {
            if (logs[i].topics[0] == IWalletFactory.ImplementationSunset.selector) {
                assertEq(logs[i].topics[1], bytes32(uint256(uint160(address(walletImplementation)))));
                found = true;
                break;
            }
        }
        assertTrue(found, "ImplementationSunset event not emitted");
    }

    // ── Additional coverage ─────────────────────────────────────────

    function test_deprecateImplementation_allImplsDeprecated() public {
        vm.prank(ADMIN);
        factory.deprecateImplementation(address(walletImplementation));

        assertEq(factory.latestWalletImpl(), address(0));
    }

    function test_deprecateImplementation_idempotent() public {
        vm.prank(ADMIN);
        factory.deprecateImplementation(address(walletImplementation));

        // Second deprecation — should still succeed (already deprecated, but codehash is still vetted)
        vm.prank(ADMIN);
        factory.deprecateImplementation(address(walletImplementation));

        assertTrue(factory.deprecatedImpls(address(walletImplementation).codehash));
    }

    /// @dev Deprecation is keyed by codehash, not address. Latest may hold
    ///      address A while the owner deprecates a different address B that
    ///      shares A's codehash (a redeploy of identical bytecode). The latest
    ///      pointer must still recompute, otherwise deployLatestWalletProxy
    ///      would deploy against a now-deprecated implementation.
    ///      `new WOTSPlusImplementation()` cannot produce a second address with
    ///      the same codehash: EIP-712 / CallContextChecker bake `address(this)`
    ///      into immutables. Copy the runtime bytecode with `vm.etch` instead,
    ///      matching `test_undeprecateImplementation_rebindsAddressForSameCodehash`.
    function test_deprecateImplementation_clearsLatestWhenSameCodehashDifferentAddress() public {
        address a = address(walletImplementation);
        assertEq(factory.latestWalletImpl(), a);

        address b = makeAddr("same-codehash-redeploy");
        vm.etch(b, a.code);
        assertEq(b.codehash, a.codehash);
        assertTrue(a != b);

        vm.prank(ADMIN);
        factory.deprecateImplementation(b);

        assertEq(factory.latestWalletImpl(), address(0));

        vm.prank(ALICE);
        vm.expectRevert(IWalletFactory.NoActiveImplementation.selector);
        factory.deployLatestWalletProxy(keccak256("same-codehash vault"), payable(ALICE), "");
    }

    // ── Reverts ──────────────────────────────────────────────────────

    function test_deprecateImplementation_revertsWhen_notVetted() public {
        vm.prank(ADMIN);
        vm.expectRevert(IWalletFactory.ImplementationNotVetted.selector);
        factory.deprecateImplementation(address(this));
    }

    function test_deprecateImplementation_revertsWhen_callerNotOwner() public {
        vm.prank(ALICE);
        vm.expectRevert(Ownable.Unauthorized.selector);
        factory.deprecateImplementation(address(walletImplementation));
    }
}
