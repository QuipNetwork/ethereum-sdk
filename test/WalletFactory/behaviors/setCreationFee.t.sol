// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {WalletFactoryTest} from "../WalletFactory.t.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.2.0/contracts/WOTSPlus.sol";
import {Ownable} from "solady-0.1.26/src/auth/Ownable.sol";
import {IWalletFactory} from "../../../contracts/interfaces/IWalletFactory.sol";
import {Vm} from "forge-std-1.14.0/Vm.sol";

contract WalletFactory_setCreationFee is WalletFactoryTest {
    function test_setCreationFee_setsFee() public {
        vm.prank(ADMIN);
        factory.setCreationFee(CREATION_FEE);

        assertEq(factory.creationFee(), CREATION_FEE);
    }

    function test_setCreationFee_collectsFees() public {
        vm.prank(ADMIN);
        factory.setCreationFee(CREATION_FEE);

        bytes32 commitment = keccak256("Vault 1");
        (WOTSPlus.WinternitzAddress memory pubkey, bytes32 privateKey) = _generateKeyPair("seed1");
        WOTSPlus.WinternitzAddress[] memory rKeys = _generateRecoveryKeys(privateKey, 10);

        uint256 factoryBalBefore = address(factory).balance;

        bytes memory payload = _encodeInitPayload(pubkey, rKeys);

        vm.prank(ALICE);
        factory.deployLatestWalletProxy{value: INITIAL_DEPOSIT + CREATION_FEE}(commitment, payable(ALICE), payload);

        assertEq(address(factory).balance, factoryBalBefore + CREATION_FEE);
    }

    function test_setCreationFee_emitsCreationFeeUpdated() public {
        vm.prank(ADMIN);
        vm.recordLogs();
        factory.setCreationFee(CREATION_FEE);

        Vm.Log[] memory logs = vm.getRecordedLogs();
        bool found = false;
        for (uint256 i = 0; i < logs.length; i++) {
            if (logs[i].topics[0] == IWalletFactory.CreationFeeUpdated.selector) {
                found = true;
                break;
            }
        }
        assertTrue(found, "CreationFeeUpdated event not emitted");
    }

    function test_setCreationFee_revertsWhen_callerNotAdmin() public {
        vm.prank(ALICE);
        vm.expectRevert(Ownable.Unauthorized.selector);
        factory.setCreationFee(CREATION_FEE);
    }

    function test_setCreationFee_setsZeroFee() public {
        vm.prank(ADMIN);
        factory.setCreationFee(CREATION_FEE);
        assertEq(factory.creationFee(), CREATION_FEE);

        vm.prank(ADMIN);
        factory.setCreationFee(0);
        assertEq(factory.creationFee(), 0);
    }

    function test_setCreationFee_setsMaxFee() public {
        uint256 maxFee = factory.MAX_FEE();
        vm.prank(ADMIN);
        factory.setCreationFee(maxFee);
        assertEq(factory.creationFee(), maxFee);
    }

    function test_setCreationFee_revertsWhen_feeExceedsMax() public {
        uint256 maxFee = factory.MAX_FEE();
        uint256 excessFee = maxFee + 1;
        vm.prank(ADMIN);
        vm.expectRevert(abi.encodeWithSelector(IWalletFactory.FeeExceedsMax.selector, excessFee, maxFee));
        factory.setCreationFee(excessFee);
    }
}
