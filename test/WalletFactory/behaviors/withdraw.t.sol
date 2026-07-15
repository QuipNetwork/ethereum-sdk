// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {WalletFactoryTest} from "../WalletFactory.t.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.2.0/contracts/WOTSPlus.sol";
import {Ownable} from "solady-0.1.26/src/auth/Ownable.sol";
import {IWalletFactory} from "../../../contracts/interfaces/IWalletFactory.sol";
import {Vm} from "forge-std-1.14.0/Vm.sol";

contract WalletFactory_withdraw is WalletFactoryTest {
    function setUp() public override {
        super.setUp();

        // Set creation fee and create a wallet to accumulate fees
        vm.prank(ADMIN);
        factory.setCreationFee(CREATION_FEE);

        bytes32 vaultId = keccak256("Fee Vault");
        (WOTSPlus.WinternitzAddress memory pubkey, bytes32 privateKey) = _generateKeyPair("seed1");
        WOTSPlus.WinternitzAddress[] memory rKeys = _generateRecoveryKeys(privateKey, 10);

        bytes memory payload = _encodeInitPayload(pubkey, rKeys);

        vm.prank(ALICE);
        factory.deployLatestWalletProxy{value: INITIAL_DEPOSIT + CREATION_FEE}(vaultId, payable(ALICE), payload);
    }

    function test_setUp() public view override {
        assertEq(factory.owner(), ADMIN);
        assertEq(factory.creationFee(), CREATION_FEE);
        assertTrue(address(factory).balance > 0);
    }

    function test_withdraw_sendsFeesToAdmin() public {
        uint256 adminBalBefore = ADMIN.balance;
        uint256 factoryBal = address(factory).balance;

        vm.prank(ADMIN);
        factory.withdraw(factoryBal);

        assertEq(address(factory).balance, 0);
        assertEq(ADMIN.balance, adminBalBefore + factoryBal);
    }

    // ── Additional coverage ─────────────────────────────────────────

    function test_withdraw_partialAmount() public {
        uint256 factoryBal = address(factory).balance;
        uint256 half = factoryBal / 2;
        uint256 adminBalBefore = ADMIN.balance;

        vm.prank(ADMIN);
        factory.withdraw(half);

        assertEq(address(factory).balance, factoryBal - half);
        assertEq(ADMIN.balance, adminBalBefore + half);
    }

    function test_withdraw_zeroAmount() public {
        uint256 factoryBal = address(factory).balance;
        uint256 adminBalBefore = ADMIN.balance;

        vm.prank(ADMIN);
        factory.withdraw(0);

        assertEq(address(factory).balance, factoryBal);
        assertEq(ADMIN.balance, adminBalBefore);
    }

    function test_withdraw_emitsWithdrawnEvent() public {
        uint256 factoryBal = address(factory).balance;

        vm.prank(ADMIN);
        vm.recordLogs();
        factory.withdraw(factoryBal);

        Vm.Log[] memory logs = vm.getRecordedLogs();
        bool found = false;
        for (uint256 i = 0; i < logs.length; i++) {
            if (logs[i].topics[0] == keccak256("Withdrawn(address,uint256)")) {
                found = true;
                break;
            }
        }
        assertTrue(found, "Withdrawn event not emitted");
    }

    function test_withdraw_revertsWhen_callerNotAdmin() public {
        vm.prank(ALICE);
        vm.expectRevert(Ownable.Unauthorized.selector);
        factory.withdraw(CREATION_FEE);
    }

    function test_withdraw_revertsWhen_insufficientBalance() public {
        uint256 bal = address(factory).balance;
        vm.prank(ADMIN);
        vm.expectRevert(abi.encodeWithSelector(IWalletFactory.InsufficientBalance.selector, 1000 ether, bal));
        factory.withdraw(1000 ether);
    }
}
