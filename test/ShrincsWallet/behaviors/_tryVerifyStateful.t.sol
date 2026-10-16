// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {SHRINCS} from "@quip.network/hashsigs-solidity-0.2.0/contracts/SHRINCS.sol";
// prettier-ignore
import {
    IERC7913SignatureVerifier
} from "@quip.network/hashsigs-solidity-0.2.0/contracts/interfaces/IERC7913SignatureVerifier.sol";
import {ShrincsWalletCodec as Codec} from "../../../contracts/shrincs/ShrincsWalletCodec.sol";
import {ShrincsWalletTest} from "../ShrincsWallet.t.sol";

/// @dev Behavior tests for the internal `_tryVerifyStateful` (via the harness) — the wallet's
///      revert-policy boundary around the external verifier's ERC-7913 `verify`. True only for
///      a valid signature over exactly the given message hash under the given commitment; every
///      verifier rejection AND every verifier revert (0.2.0's revert-as-rejection channel for
///      garbage signature internals) maps to false. Only a codeless verifier stays loud.
contract ShrincsWallet__tryVerifyStateful is ShrincsWalletTest {
    bytes32 internal constant PAYLOAD = keccak256("try-verify-stateful-payload");

    /// @dev A valid (messageHash, envelope) pair over the wallet's canonical EXECUTE context.
    function _validPair() internal view returns (bytes32 messageHash, bytes memory envelope) {
        SHRINCS.ActionContext memory ctx = _actionContext(Codec.ACTION_EXECUTE, PAYLOAD);
        messageHash = SHRINCS.statefulActionMessageHash(mainCommitment, ctx);
        SHRINCS.Signature memory sig = _signStatefulAction(Codec.ACTION_EXECUTE, PAYLOAD, 1);
        envelope = abi.encode(mainPk, sig);
    }

    function test_tryVerifyStateful_trueForValidSignature() public {
        (bytes32 messageHash, bytes memory envelope) = _validPair();
        vm.expectCall(
            address(shrincsVerifier), abi.encodeWithSelector(IERC7913SignatureVerifier.verify.selector)
        );
        assertTrue(wallet.exposed_tryVerifyStateful(mainCommitment, messageHash, envelope));
    }

    function test_tryVerifyStateful_falseWhen_wrongMessageHash() public view {
        (, bytes memory envelope) = _validPair();
        assertFalse(
            wallet.exposed_tryVerifyStateful(mainCommitment, keccak256("some other message"), envelope)
        );
    }

    function test_tryVerifyStateful_falseWhen_commitmentMismatch() public view {
        (bytes32 messageHash, bytes memory envelope) = _validPair();
        // The verifier's bundle-vs-commitment check rejects a foreign expected commitment.
        assertFalse(
            wallet.exposed_tryVerifyStateful(erc1271Commitment, messageHash, envelope)
        );
    }

    /// @dev The revert-as-rejection policy pin: a well-formed envelope whose signature
    ///      internals are garbage (empty arrays) REVERTS inside the verifier — 0.2.0 dropped
    ///      the shape walk — and the try/catch must report it as plain false.
    function test_tryVerifyStateful_falseWhen_garbageSignatureInternals() public view {
        SHRINCS.Signature memory garbage;
        garbage.authPath = new bytes32[](1); // in-budget leaf shape, empty chains
        assertFalse(
            wallet.exposed_tryVerifyStateful(
                mainCommitment, keccak256("any message"), abi.encode(mainPk, garbage)
            )
        );
    }

    /// @dev A missing verifier must stay LOUD: solc's return-data check on the codeless call
    ///      raises a decoding error, which try/catch deliberately does not swallow — never
    ///      misread as a mere invalid signature.
    function test_tryVerifyStateful_revertsWhen_verifierCodeRemoved() public {
        (bytes32 messageHash, bytes memory envelope) = _validPair();
        vm.etch(address(shrincsVerifier), "");
        vm.expectRevert();
        wallet.exposed_tryVerifyStateful(mainCommitment, messageHash, envelope);
    }
}
