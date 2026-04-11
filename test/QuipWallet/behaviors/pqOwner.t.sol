// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {QuipWalletTest} from "../QuipWallet.t.sol";

contract QuipWallet_pqOwner is QuipWalletTest {
    function test_pqOwner_returnsCorrectInitialValues() public view {
        (bytes32 publicSeed, bytes32 publicKeyHash) = wallet.pqOwner();
        assertEq(publicSeed, alicePubkey.publicSeed);
        assertEq(publicKeyHash, alicePubkey.publicKeyHash);
    }

    function test_pqOwner_returnsNonZeroValues() public view {
        (bytes32 publicSeed, bytes32 publicKeyHash) = wallet.pqOwner();
        assertTrue(publicSeed != bytes32(0));
        assertTrue(publicKeyHash != bytes32(0));
    }
}
