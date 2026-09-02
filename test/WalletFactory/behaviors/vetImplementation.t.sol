// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {WalletFactoryTest} from "../WalletFactory.t.sol";
import {WOTSPlusImplementation} from "../../../contracts/deprecated/wots/WOTSPlusImplementation.sol";
import {IWalletFactory} from "../../../contracts/interfaces/IWalletFactory.sol";
import {Ownable} from "solady-0.1.26/src/auth/Ownable.sol";
import {Vm} from "forge-std-1.14.0/Vm.sol";

contract WalletFactory_vetImplementation is WalletFactoryTest {
    // ── Happy paths ──────────────────────────────────────────────────

    function test_vetImplementation_addsCodehash() public {
        // setUp already vets walletImplementation, so count starts at 1
        assertEq(factory.getVettedCodeCount(), 1);
        assertEq(factory.vettedWalletImpls(address(walletImplementation).codehash), address(walletImplementation));
    }

    function test_vetImplementation_setsLatestWalletImpl() public {
        WOTSPlusImplementation impl2 = new WOTSPlusImplementation(payable(address(factory)));
        vm.prank(ADMIN);
        factory.vetImplementation(address(impl2));

        assertEq(factory.latestWalletImpl(), address(impl2));
    }

    function test_vetImplementation_emitsImplementationVetted() public {
        WOTSPlusImplementation impl2 = new WOTSPlusImplementation(payable(address(factory)));

        vm.prank(ADMIN);
        vm.recordLogs();
        factory.vetImplementation(address(impl2));

        Vm.Log[] memory logs = vm.getRecordedLogs();
        bool found = false;
        for (uint256 i = 0; i < logs.length; i++) {
            if (logs[i].topics[0] == IWalletFactory.ImplementationVetted.selector) {
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
        vm.expectRevert(IWalletFactory.EmptyCode.selector);
        factory.vetImplementation(address(0xdead));
    }

    /// @dev EIP-1052: a codeless account that has held a balance reports
    ///      `keccak256("")`, not zero. A `codehash == 0` guard would admit it; the
    ///      code-length guard must not.
    function test_vetImplementation_revertsWhen_touchedEoa_balance() public {
        address eoa = address(0xE0A1);
        vm.deal(eoa, 1 wei);
        assertEq(eoa.codehash, keccak256(""), "precondition: touched EOA has nonzero codehash");
        assertEq(eoa.code.length, 0);

        vm.prank(ADMIN);
        vm.expectRevert(IWalletFactory.EmptyCode.selector);
        factory.vetImplementation(eoa);
        assertEq(factory.getVettedCodeCount(), 1);
        assertEq(factory.latestWalletImpl(), address(walletImplementation));
    }

    /// @dev Same trap via a nonzero nonce (an address that has sent a transaction).
    function test_vetImplementation_revertsWhen_touchedEoa_nonce() public {
        address eoa = address(0xE0A2);
        vm.setNonce(eoa, 1);
        assertEq(eoa.codehash, keccak256(""), "precondition: touched EOA has nonzero codehash");

        vm.prank(ADMIN);
        vm.expectRevert(IWalletFactory.EmptyCode.selector);
        factory.vetImplementation(eoa);
        assertEq(factory.getVettedCodeCount(), 1);
    }

    /// @dev The empty codehash must never enter the vetted set: it is shared by every
    ///      touched EOA, so one entry would "vet" all of them.
    function test_vetImplementation_neverVetsEmptyCodehash() public {
        address eoa = address(0xE0A3);
        vm.deal(eoa, 1 ether);
        vm.prank(ADMIN);
        vm.expectRevert(IWalletFactory.EmptyCode.selector);
        factory.vetImplementation(eoa);
        assertEq(factory.getVettedCodeIndex(keccak256("")), type(uint256).max);
        assertEq(factory.vettedWalletImpls(keccak256("")), address(0));
    }

    function test_vetImplementation_revertsWhen_callerNotOwner() public {
        vm.prank(ALICE);
        vm.expectRevert(Ownable.Unauthorized.selector);
        factory.vetImplementation(address(walletImplementation));
    }

    /// @dev Re-vetting a codehash that's already in the vetted set must revert,
    ///      regardless of its deprecation status. Reactivation flows through
    ///      `undeprecateImplementation` so observers can reconstruct the
    ///      vet/sunset/undeprecate lifecycle from events alone.
    function test_vetImplementation_revertsWhen_alreadyVettedAndActive() public {
        vm.prank(ADMIN);
        vm.expectRevert(IWalletFactory.AlreadyVetted.selector);
        factory.vetImplementation(address(walletImplementation));
    }

    function test_vetImplementation_revertsWhen_alreadyVettedAndDeprecated() public {
        vm.prank(ADMIN);
        factory.deprecateImplementation(address(walletImplementation));

        vm.prank(ADMIN);
        vm.expectRevert(IWalletFactory.AlreadyVetted.selector);
        factory.vetImplementation(address(walletImplementation));
    }
}
