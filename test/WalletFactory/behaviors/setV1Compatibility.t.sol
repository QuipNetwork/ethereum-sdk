// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {Ownable} from "solady-0.1.26/src/auth/Ownable.sol";
import {IWalletFactory} from "../../../contracts/interfaces/IWalletFactory.sol";
import {WOTSPlusImplementation} from "../../../contracts/deprecated/wots/WOTSPlusImplementation.sol";
import {WalletFactoryTest} from "../WalletFactory.t.sol";

contract WalletFactory_setV1Compatibility is WalletFactoryTest {
    function test_setV1Compatibility_setsAndRevokesCertification() public {
        bytes32 codehash = address(walletImplementation).codehash;
        assertTrue(factory.v1CompatibleImplementations(codehash));

        vm.prank(ADMIN);
        factory.setV1Compatibility(address(walletImplementation), false);
        assertFalse(factory.v1CompatibleImplementations(codehash));
    }

    function test_setV1Compatibility_emitsV1CompatibilitySet() public {
        bytes32 codehash = address(walletImplementation).codehash;

        vm.prank(ADMIN);
        vm.expectEmit(true, true, false, true, address(factory));
        emit IWalletFactory.V1CompatibilitySet(
            address(walletImplementation),
            codehash,
            false
        );
        factory.setV1Compatibility(address(walletImplementation), false);
    }

    function test_setV1Compatibility_revertsWhen_callerNotOwner() public {
        vm.prank(ALICE);
        vm.expectRevert(Ownable.Unauthorized.selector);
        factory.setV1Compatibility(address(walletImplementation), false);
    }

    function test_setV1Compatibility_revertsWhen_implementationNotVetted()
        public
    {
        WOTSPlusImplementation unvetted = new WOTSPlusImplementation(
            payable(address(factory))
        );

        vm.prank(ADMIN);
        vm.expectRevert(IWalletFactory.ImplementationNotVetted.selector);
        factory.setV1Compatibility(address(unvetted), true);
    }
}
