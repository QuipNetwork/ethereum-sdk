// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {ShrincsWalletTest} from "../ShrincsWallet.t.sol";
import {ShrincsWalletCodec as Codec} from "../../../contracts/shrincs/ShrincsWalletCodec.sol";
import {SHRINCS} from "@quip.network/hashsigs-solidity-0.2.0/contracts/SHRINCS.sol";
import {IERC7913SignatureVerifier} from "@quip.network/hashsigs-solidity-0.2.0/contracts/interfaces/IERC7913SignatureVerifier.sol";

/// @title ShrincsWallet — _tryVerifyStateful differential vs the reference verifier
/// @dev Pins accept/reject agreement between the wallet's `_tryVerifyStateful`
///      policy boundary and a direct call to the pinned SHRINCS verifier over
///      identical (commitment, messageHash, envelope) triples. Any divergence
///      means the wallet's framing drifted from what the verifier expects.
///      Covers INVARIANTS.md §19 (every verifier revert maps to rejection).
contract ShrincsWallet__tryVerifyDifferential is ShrincsWalletTest {
    struct Triple {
        bytes32 commitment;
        bytes32 messageHash;
        bytes envelope;
        SHRINCS.PublicKey pk;
        SHRINCS.Signature sig;
    }

    function _validTriple() internal view returns (Triple memory t) {
        uint32[] memory targets = new uint32[](1);
        targets[0] = SIGN_BASE + 2;
        bytes memory packed;
        packed = abi.encodePacked(packed, bytes32(uint256(targets[0])));
        bytes32 payloadHash = Codec.markLeavesUsedPayloadHash(
            keccak256(packed)
        );
        SHRINCS.ActionContext memory ctx = _actionContext(
            Codec.ACTION_MARK_LEAVES_USED,
            payloadHash
        );
        t.commitment = wallet.getShrincsPublicKeyCommitment();
        t.messageHash = SHRINCS.statefulActionMessageHash(t.commitment, ctx);
        t.pk = _mainPk();
        t.sig = _signStatefulAction(
            Codec.ACTION_MARK_LEAVES_USED,
            payloadHash,
            1
        );
        t.envelope = abi.encode(t.pk, t.sig);
    }

    function _walletVerify(
        bytes32 commitment,
        bytes32 messageHash,
        bytes memory envelope
    ) internal view returns (bool) {
        return
            wallet.exposed_tryVerifyStateful(commitment, messageHash, envelope);
    }

    function _referenceVerify(
        bytes32 commitment,
        bytes32 messageHash,
        bytes memory envelope
    ) internal view returns (bool) {
        try
            IERC7913SignatureVerifier(address(shrincsVerifier)).verify(
                abi.encodePacked(commitment),
                messageHash,
                envelope
            )
        returns (bytes4 result) {
            return result == IERC7913SignatureVerifier.verify.selector;
        } catch {
            return false;
        }
    }

    function test_exposed_tryVerifyStateful_acceptsValidSignature()
        public
        view
    {
        Triple memory t = _validTriple();
        assertTrue(
            _walletVerify(t.commitment, t.messageHash, t.envelope),
            "wallet rejected valid"
        );
        assertTrue(
            _referenceVerify(t.commitment, t.messageHash, t.envelope),
            "reference rejected valid"
        );
    }

    function test_exposed_tryVerifyStateful_rejectsCorruptedSignature()
        public
        view
    {
        Triple memory t = _validTriple();
        if (t.sig.chains.length > 0) {
            t.sig.chains[0] = bytes32(uint256(t.sig.chains[0]) ^ 1);
        } else {
            t.sig.authPath[0] = bytes32(uint256(t.sig.authPath[0]) ^ 1);
        }
        t.envelope = abi.encode(t.pk, t.sig);
        assertFalse(
            _walletVerify(t.commitment, t.messageHash, t.envelope),
            "wallet accepted corrupt"
        );
        assertFalse(
            _referenceVerify(t.commitment, t.messageHash, t.envelope),
            "reference accepted corrupt"
        );
    }

    function test_exposed_tryVerifyStateful_rejectsWrongCommitment()
        public
        view
    {
        Triple memory t = _validTriple();
        bytes32 wrong = keccak256("shrincs-wallet-tryVerify-wrong-commitment");
        assertFalse(
            _walletVerify(wrong, t.messageHash, t.envelope),
            "wallet accepted wrong commitment"
        );
        assertFalse(
            _referenceVerify(wrong, t.messageHash, t.envelope),
            "reference accepted wrong commitment"
        );
    }

    function test_exposed_tryVerifyStateful_rejectsTruncatedEnvelope()
        public
        view
    {
        Triple memory t = _validTriple();
        bytes memory cut = new bytes(t.envelope.length - 1);
        for (uint256 i = 0; i < cut.length; i++) {
            cut[i] = t.envelope[i];
        }
        assertFalse(
            _walletVerify(t.commitment, t.messageHash, cut),
            "wallet accepted truncated"
        );
        assertFalse(
            _referenceVerify(t.commitment, t.messageHash, cut),
            "reference accepted truncated"
        );
    }

    function test_exposed_tryVerifyStateful_rejectsEmptyEnvelope() public view {
        Triple memory t = _validTriple();
        assertFalse(
            _walletVerify(t.commitment, t.messageHash, new bytes(0)),
            "wallet accepted empty"
        );
        assertFalse(
            _referenceVerify(t.commitment, t.messageHash, new bytes(0)),
            "reference accepted empty"
        );
    }
}
