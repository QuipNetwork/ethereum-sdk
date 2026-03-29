// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {QuipFactoryTest} from "../QuipFactory.t.sol";
import {QuipWallet} from "../../../contracts/QuipWallet.sol";
import {IQuipFactory} from "../../../contracts/interfaces/IQuipFactory.sol";
import {Ownable} from "@openzeppelin-contracts-5.6.0-rc.1/access/Ownable.sol";
import {Vm} from "forge-std-1.14.0/Vm.sol";

contract QuipFactory_deprecateImplementation is QuipFactoryTest {
    // ── Happy paths ──────────────────────────────────────────────────

    function test_deprecateImplementation_marksDeprecated() public {
        vm.prank(ADMIN);
        factory.deprecateImplementation(address(walletImplementation));

        assertTrue(factory.deprecatedImpls(address(walletImplementation).codehash));
    }

    function test_deprecateImplementation_updatesLatestWalletImpl() public {
        // Vet a second implementation
        QuipWallet impl2 = new QuipWallet(payable(address(factory)));
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
            if (logs[i].topics[0] == IQuipFactory.ImplementationSunset.selector) {
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

    // ── Reverts ──────────────────────────────────────────────────────

    function test_deprecateImplementation_revertsWhen_notVetted() public {
        vm.prank(ADMIN);
        vm.expectRevert(IQuipFactory.ImplementationNotVetted.selector);
        factory.deprecateImplementation(address(this));
    }

    function test_deprecateImplementation_revertsWhen_callerNotOwner() public {
        vm.prank(ALICE);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, ALICE));
        factory.deprecateImplementation(address(walletImplementation));
    }
}
