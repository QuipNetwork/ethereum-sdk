// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {PackedUserOperation} from "@openzeppelin-contracts-5.6.0-rc.1/interfaces/draft-IERC4337.sol";
import {ShrincsE2EBase} from "./ShrincsE2EBase.t.sol";

/// @dev e2e key-rotation: rotating the paymaster's global verifier (owner-only) bumps its epoch and
///      starts a fresh leaf namespace under a new commitment. An op signed under the OLD key is then
///      rejected, while an op signed under the NEW key (epoch 1) is sponsored.
contract ShrincsE2E_keyRotation is ShrincsE2EBase {
    function _rotateToVerifier2() internal {
        vm.prank(ADMIN);
        paymaster.setShrincsVerifier(
            _bytes32(".verifierKey2.publicKeyCommitment"),
            uint8(vm.parseJsonUint(vectors, ".verifierKey2.parameterSetId")),
            MAX_SIG
        );
        (, , uint256 keyVersion, , ) = paymaster.getShrincsVerifier();
        assertEq(keyVersion, 1, "paymaster epoch bumped to 1");
    }

    /// @dev After rotation, a sponsorship signed by the NEW verifier key under epoch 1 is accepted.
    function test_e2e_paymasterRotation_newKeyAccepted() public {
        _rotateToVerifier2();

        uint256 pmDepositBefore = _deposit(PAYMASTER);
        _handle(_op("paymasterRotationNewKey")); // signed with verifierKey2, paymaster keyVersion 1

        assertLt(_deposit(PAYMASTER), pmDepositBefore, "paymaster paid gas");
        assertTrue(paymaster.isStatefulLeafUsed(1), "epoch-1 leaf 1 consumed");
    }

    /// @dev After rotation, the stored commitment is the new key, so an op carrying the OLD verifier
    ///      key fails `matchesExpectedPublicKeyCommitment` inside `verifyStateful` → `AA34`.
    function test_e2e_paymasterRotation_oldKeyRejected() public {
        _rotateToVerifier2();
        // sponsoredEthTransfer's paymaster blob is the OLD verifierKey, signed under epoch 0.
        _handleExpectRevert(
            _op("sponsoredEthTransfer"),
            _failedOp(0, "AA34 signature error")
        );
    }

    /// @dev A leaf consumed pre-rotation reads unused post-rotation — the new epoch is a fresh
    ///      namespace (consume-once is per-epoch, not global).
    function test_e2e_paymasterRotation_freshLeafNamespace() public {
        _handle(_op("sponsoredEthTransfer")); // consumes epoch-0 paymaster leaf 1
        assertTrue(paymaster.isStatefulLeafUsed(1), "epoch-0 leaf 1 used");

        _rotateToVerifier2();
        assertFalse(
            paymaster.isStatefulLeafUsed(1),
            "epoch-1 leaf 1 is a fresh, unused namespace"
        );
    }

    /// @dev Wallet-side rotation: a real owner-gated `rotateKey` (PQ-signed, leaf 5 under epoch 0)
    ///      installs a new commitment and bumps the wallet epoch. An OLD-epoch sponsorship — whose
    ///      wallet signature is bound to the prior key/epoch — is then rejected by the account →
    ///      `AA24` (the EntryPoint nonce is untouched by the direct `rotateKey` call).
    function test_e2e_walletRotation_oldEpochSigRejected() public {
        bytes32 nextCommitment = _bytes32(
            ".cases.walletRotateKey.nextCommitment"
        );

        vm.prank(WALLET_OWNER);
        wallet.rotateKey(
            _parsePublicKey(".walletKey"),
            _parseStatefulSignature(".cases.walletRotateKey.signature"),
            _parseStatefulRotationTarget(
                ".cases.walletRotateKey.nextStatefulKey"
            )
        );

        // A successful rotateKey proves the leaf-5 signature verified (else it reverts); the new
        // commitment confirms the rotation landed. The consumed leaf lived in epoch 0, so it is
        // (correctly) invisible under the new current epoch 1.
        assertEq(
            wallet.getShrincsPublicKeyCommitment(),
            nextCommitment,
            "wallet rotated to the new commitment"
        );

        // The pre-rotation sponsorship (wallet sig under the old key/epoch) no longer validates.
        _handleExpectRevert(
            _op("sponsoredEthTransfer"),
            _failedOp(0, "AA24 signature error")
        );
    }
}
