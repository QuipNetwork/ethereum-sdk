// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.28;

import {QuipFactoryTest} from "../QuipFactory.t.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.1.0/contracts/WOTSPlus.sol";

contract QuipFactory_setCreationFee is QuipFactoryTest {
    function test_setCreationFee_setsFee() public {
        vm.prank(ADMIN);
        factory.setCreationFee(CREATION_FEE);

        assertEq(factory.creationFee(), CREATION_FEE);
    }

    function test_setCreationFee_collectsFees() public {
        vm.prank(ADMIN);
        factory.setCreationFee(CREATION_FEE);

        bytes32 vaultId = keccak256("Vault 1");
        (WOTSPlus.WinternitzAddress memory pubkey,) = _generateKeyPair("seed1");

        uint256 factoryBalBefore = address(factory).balance;

        vm.prank(ALICE);
        factory.depositToWinternitz{value: INITIAL_DEPOSIT + CREATION_FEE}(
            vaultId,
            payable(ALICE),
            pubkey
        );

        assertEq(address(factory).balance, factoryBalBefore + CREATION_FEE);
    }

    function test_setCreationFee_revertsWhen_callerNotAdmin() public {
        vm.prank(ALICE);
        vm.expectRevert("You aren't the admin");
        factory.setCreationFee(CREATION_FEE);
    }
}
