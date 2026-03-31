// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {QuipFactoryTest} from "../QuipFactory.t.sol";
import {QuipWallet} from "../../../contracts/QuipWallet.sol";
import {IQuipFactory} from "../../../contracts/interfaces/IQuipFactory.sol";
import {Ownable} from "@openzeppelin-contracts-5.6.0-rc.1/access/Ownable.sol";
import {Vm} from "forge-std-1.14.0/Vm.sol";

contract QuipFactory_vetImplementation is QuipFactoryTest {
    // ── Happy paths ──────────────────────────────────────────────────

    function test_vetImplementation_addsCodehash() public {
        // setUp already vets walletImplementation, so count starts at 1
        assertEq(factory.getVettedCodeCount(), 1);
        assertEq(
            factory.vettedWalletImpls(address(walletImplementation).codehash),
            address(walletImplementation)
        );
    }

    function test_vetImplementation_reactivatesDeprecated() public {
        // Vet a second impl so latestWalletImpl points to it
        QuipWallet impl2 = new QuipWallet(payable(address(factory)));
        vm.prank(ADMIN);
        factory.vetImplementation(address(impl2));
        assertEq(factory.latestWalletImpl(), address(impl2));

        vm.prank(ADMIN);
        factory.deprecateImplementation(address(walletImplementation));
        assertTrue(factory.deprecatedImpls(address(walletImplementation).codehash));

        // Re-activate the first impl — latestWalletImpl should NOT change
        vm.prank(ADMIN);
        factory.vetImplementation(address(walletImplementation));
        assertFalse(factory.deprecatedImpls(address(walletImplementation).codehash));
        assertEq(factory.latestWalletImpl(), address(impl2));
    }

    function test_vetImplementation_setsLatestWalletImpl() public {
        QuipWallet impl2 = new QuipWallet(payable(address(factory)));
        vm.prank(ADMIN);
        factory.vetImplementation(address(impl2));

        assertEq(factory.latestWalletImpl(), address(impl2));
    }

    function test_vetImplementation_emitsImplementationVetted() public {
        QuipWallet impl2 = new QuipWallet(payable(address(factory)));

        vm.prank(ADMIN);
        vm.recordLogs();
        factory.vetImplementation(address(impl2));

        Vm.Log[] memory logs = vm.getRecordedLogs();
        bool found = false;
        for (uint256 i = 0; i < logs.length; i++) {
            if (logs[i].topics[0] == IQuipFactory.ImplementationVetted.selector) {
                assertEq(logs[i].topics[1], bytes32(uint256(uint160(address(impl2)))));
                found = true;
                break;
            }
        }
        assertTrue(found, "ImplementationVetted event not emitted");
    }

    // ── Reverts ──────────────────────────────────────────────────────

    function test_vetImplementation_revertsWhen_emptyCode() public {
        vm.prank(ADMIN);
        vm.expectRevert(IQuipFactory.EmptyCode.selector);
        factory.vetImplementation(address(0xdead));
    }

    function test_vetImplementation_revertsWhen_callerNotOwner() public {
        vm.prank(ALICE);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, ALICE));
        factory.vetImplementation(address(walletImplementation));
    }

    function test_vetImplementation_reVetUpdatesLatestWhenNoneActive() public {
        vm.prank(ADMIN);
        factory.deprecateImplementation(address(walletImplementation));
        assertEq(factory.latestWalletImpl(), address(0));

        vm.prank(ADMIN);
        factory.vetImplementation(address(walletImplementation));
        assertEq(factory.latestWalletImpl(), address(walletImplementation));
    }

    function test_vetImplementation_reVetDoesNotChangeLatestWhenOneActive() public {
        QuipWallet impl2 = new QuipWallet(payable(address(factory)));
        vm.prank(ADMIN);
        factory.vetImplementation(address(impl2));

        vm.prank(ADMIN);
        factory.deprecateImplementation(address(walletImplementation));

        assertEq(factory.latestWalletImpl(), address(impl2));

        vm.prank(ADMIN);
        factory.vetImplementation(address(walletImplementation));
        assertEq(factory.latestWalletImpl(), address(impl2));
    }
}
