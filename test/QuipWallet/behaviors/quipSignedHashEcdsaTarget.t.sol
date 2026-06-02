// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {QuipWalletTest} from "../QuipWallet.t.sol";
import {QuipWallet} from "../../../contracts/QuipWallet.sol";

/// @title QuipWallet.quipSignedHashEcdsaTarget — view parity & binding
/// @dev `quipSignedHashEcdsaTarget(hash)` returns the exact 32-byte digest
///      the ECDSA half of `isValidSignature` will recover against. This
///      file pins:
///        1. byte-for-byte equality with a hand-rolled EIP-712 computation
///           (`keccak256(0x1901 || domainSeparator || structHash)`), so any
///           drift in Solady's `_hashTypedData`, the wallet's
///           `_domainNameAndVersion`, or the `_QUIP_SIGNED_HASH_TYPEHASH`
///           constant surfaces immediately;
///        2. that the result binds to the wallet address (replay across
///           QuipWallets sharing an `owner()` is impossible);
///        3. that the result binds to `chainId` (cross-chain replay is
///           impossible);
///        4. distinct hashes produce distinct targets (sanity).
contract QuipWallet_quipSignedHashEcdsaTarget is QuipWalletTest {
    function test_quipSignedHashEcdsaTarget_matchesIndependentEip712Computation()
        public
        view
    {
        bytes32 hash = keccak256("erc1271-target-parity");
        bytes32 expected = _buildErc1271EcdsaTarget(address(wallet), hash);
        bytes32 actual = wallet.quipSignedHashEcdsaTarget(hash);
        assertEq(
            actual,
            expected,
            "wallet view diverged from hand-rolled EIP-712 computation"
        );
    }

    function testFuzz_quipSignedHashEcdsaTarget_matchesIndependentComputation(
        bytes32 hash
    ) public view {
        assertEq(
            wallet.quipSignedHashEcdsaTarget(hash),
            _buildErc1271EcdsaTarget(address(wallet), hash)
        );
    }

    function test_quipSignedHashEcdsaTarget_bindsToWalletAddress() public {
        bytes32 hash = keccak256("erc1271-wallet-binding");
        bytes32 thisWalletTarget = wallet.quipSignedHashEcdsaTarget(hash);

        // Deploy a second QuipWallet via the factory so its EIP-712
        // `verifyingContract` differs. Same `hash` must yield a different
        // target.
        address otherOwner = makeAddr("erc1271-other-owner");
        (address otherAddr, , , ) = _createWallet(
            otherOwner,
            "erc1271-other-vault",
            0
        );
        QuipWallet otherWallet = QuipWallet(payable(otherAddr));
        bytes32 otherWalletTarget = otherWallet.quipSignedHashEcdsaTarget(hash);

        assertTrue(
            thisWalletTarget != otherWalletTarget,
            "two distinct wallets produced identical ECDSA targets for the same hash"
        );
        // Belt-and-suspenders: independent recomputation against the other
        // wallet's address agrees with its view.
        assertEq(
            otherWalletTarget,
            _buildErc1271EcdsaTarget(address(otherWallet), hash)
        );
    }

    function test_quipSignedHashEcdsaTarget_bindsToChainId() public {
        bytes32 hash = keccak256("erc1271-chain-binding");
        bytes32 onChainBefore = wallet.quipSignedHashEcdsaTarget(hash);

        vm.chainId(block.chainid + 1);
        bytes32 onChainAfter = wallet.quipSignedHashEcdsaTarget(hash);

        assertTrue(
            onChainBefore != onChainAfter,
            "ECDSA target did not change after chainId shift"
        );
    }

    function test_quipSignedHashEcdsaTarget_distinctForDistinctHashes()
        public
        view
    {
        bytes32 a = wallet.quipSignedHashEcdsaTarget(keccak256("hash-A"));
        bytes32 b = wallet.quipSignedHashEcdsaTarget(keccak256("hash-B"));
        assertTrue(
            a != b,
            "distinct hashes collided to identical ECDSA targets"
        );
    }

    function testFuzz_quipSignedHashEcdsaTarget_neverCollides(
        bytes32 hashA,
        bytes32 hashB
    ) public view {
        vm.assume(hashA != hashB);
        assertTrue(
            wallet.quipSignedHashEcdsaTarget(hashA) !=
                wallet.quipSignedHashEcdsaTarget(hashB)
        );
    }
}
