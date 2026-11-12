// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {SHRINCS} from "@quip.network/hashsigs-solidity-0.4.0/contracts/SHRINCS.sol";
import {StatelessLayout} from "@quip.network/hashsigs-solidity-0.4.0/contracts/StatelessLayout.sol";
import {SHRINCSTestCodec} from "@quip.network/hashsigs-solidity-0.4.0/test/helpers/SHRINCSTestCodec.sol";
import {StatelessSignatureTypes} from
    "@quip.network/hashsigs-solidity-0.4.0/test/helpers/StatelessSignatureTypes.sol";
import {ShrincsWalletCodecTest} from "../ShrincsWalletCodec.t.sol";

/// @dev Behavior tests for `tryEncodeStatelessPayload`: the wallet-side builder of the verifier's
///      stateless payload `PK ‖ PQ` for the paths that receive the key as an ABI struct
///      (`recoverWallet`, `transferOwnership`, the `verifyUpgrade` probe).
///
///      The function never reverts. It REJECTS a mis-sized key by returning `(false, "")`; the
///      `returnsFalseWhen_` tests assert that return value. Its callers turn the rejection into
///      their own outcome (`_statelessRotate` returns zero, `verifyUpgrade` reverts
///      `InvalidSignature`).
contract ShrincsWalletCodec_tryEncodeStatelessPayload is ShrincsWalletCodecTest {
    /// @dev Upstream golden vectors for the fixed layout (hashsigs-solidity, 256s profile).
    string internal constant GOLDEN_VECTORS =
        "dependencies/@quip.network-hashsigs-solidity-0.4.0/test/test_vectors/stateless-compact-256s.json";

    function _assertRejected(SHRINCS.PublicKey memory pk, string memory why) internal view {
        (bool ok, bytes memory payload) = codec.exposed_tryEncodeStatelessPayload(pk, _sampleStatelessSig());
        assertFalse(ok, why);
        assertEq(payload.length, 0, "a rejected key yields an empty payload");
    }

    function test_tryEncodeStatelessPayload_packsFieldsInLayoutOrder() public view {
        SHRINCS.PublicKey memory pk = _samplePublicKey();
        bytes memory pq = _sampleStatelessSig();
        (bool ok, bytes memory payload) = codec.exposed_tryEncodeStatelessPayload(pk, pq);
        assertTrue(ok, "well-sized key encodes");
        assertEq(
            payload,
            abi.encodePacked(pk.statefulPublicKey, pk.publicKeyCommitment, pk.pkSeed, pk.hypertreeRoot, pq),
            "PK || PQ"
        );
        assertEq(payload.length, StatelessLayout.PK_LEN + pq.length, "PK section has the layout width");
    }

    /// @dev The PQ length is the verifier's check, not the codec's: any `pq` is appended as-is.
    function test_tryEncodeStatelessPayload_doesNotCheckPqLength() public view {
        (bool ok, bytes memory payload) = codec.exposed_tryEncodeStatelessPayload(_samplePublicKey(), "");
        assertTrue(ok, "empty pq still encodes");
        assertEq(payload.length, StatelessLayout.PK_LEN, "payload is the PK section alone");
    }

    /// @dev The wallet's concatenation reproduces upstream's golden `compactPayload` byte-for-byte
    ///      from the same key and signature in their struct (ABI envelope) form.
    function test_tryEncodeStatelessPayload_matchesUpstreamGoldenVector() public view {
        string memory json = vm.readFile(GOLDEN_VECTORS);
        (SHRINCS.PublicKey memory pk, StatelessSignatureTypes.Signature memory sig) = abi.decode(
            vm.parseJsonBytes(json, ".vectors.valid.abiEnvelope"),
            (SHRINCS.PublicKey, StatelessSignatureTypes.Signature)
        );
        bytes memory pq = SHRINCSTestCodec.encodeCompactSignature(sig);
        assertEq(pq.length, StatelessLayout.PQ_LEN, "golden PQ section has the layout width");
        (bool ok, bytes memory payload) = codec.exposed_tryEncodeStatelessPayload(pk, pq);
        assertTrue(ok, "golden key encodes");
        assertEq(payload.length, StatelessLayout.PAYLOAD_LEN, "payload has the layout width");
        assertEq(
            keccak256(payload),
            keccak256(vm.parseJsonBytes(json, ".vectors.valid.compactPayload")),
            "payload equals the upstream golden bytes"
        );
    }

    function test_tryEncodeStatelessPayload_returnsFalseWhen_statefulPublicKeyMisSized() public view {
        SHRINCS.PublicKey memory pk = _samplePublicKey();
        pk.statefulPublicKey = bytes.concat(pk.statefulPublicKey, hex"00");
        _assertRejected(pk, "long statefulPublicKey rejected");
        pk.statefulPublicKey = new bytes(StatelessLayout.STATEFUL_PUBLIC_KEY_LEN - 1);
        _assertRejected(pk, "short statefulPublicKey rejected");
    }

    function test_tryEncodeStatelessPayload_returnsFalseWhen_publicKeyCommitmentMisSized() public view {
        SHRINCS.PublicKey memory pk = _samplePublicKey();
        pk.publicKeyCommitment = new bytes(33);
        _assertRejected(pk, "long publicKeyCommitment rejected");
        pk.publicKeyCommitment = new bytes(31);
        _assertRejected(pk, "short publicKeyCommitment rejected");
    }

    function test_tryEncodeStatelessPayload_returnsFalseWhen_pkSeedMisSized() public view {
        SHRINCS.PublicKey memory pk = _samplePublicKey();
        pk.pkSeed = new bytes(33);
        _assertRejected(pk, "long pkSeed rejected");
        pk.pkSeed = new bytes(31);
        _assertRejected(pk, "short pkSeed rejected");
    }

    function test_tryEncodeStatelessPayload_returnsFalseWhen_hypertreeRootMisSized() public view {
        SHRINCS.PublicKey memory pk = _samplePublicKey();
        pk.hypertreeRoot = new bytes(33);
        _assertRejected(pk, "long hypertreeRoot rejected");
        pk.hypertreeRoot = new bytes(0);
        _assertRejected(pk, "empty hypertreeRoot rejected");
    }

    /// @dev Mis-sized fields that still sum to `PK_LEN` would be re-split at the fixed offsets by
    ///      the verifier. The codec rejects them before the payload is built.
    function test_tryEncodeStatelessPayload_returnsFalseWhen_fieldBoundaryShifted() public view {
        SHRINCS.PublicKey memory pk = _samplePublicKey();
        pk.pkSeed = new bytes(31);
        pk.hypertreeRoot = new bytes(33);
        assertEq(
            pk.statefulPublicKey.length + pk.publicKeyCommitment.length + pk.pkSeed.length + pk.hypertreeRoot.length,
            StatelessLayout.PK_LEN,
            "fixture: total width is unchanged"
        );
        _assertRejected(pk, "shifted field boundary rejected");
    }
}
