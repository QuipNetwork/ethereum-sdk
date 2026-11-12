// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {StatelessLayout} from "@quip.network/hashsigs-solidity-0.4.0/contracts/StatelessLayout.sol";
import {SHRINCS} from "@quip.network/hashsigs-solidity-0.4.0/contracts/SHRINCS.sol";
import {UXMSS} from "@quip.network/hashsigs-solidity-0.4.0/contracts/UXMSS.sol";
import {HashSuite} from "shrincs-hash/HashSuite.sol";
import {SHRINCSParams} from "shrincs-profile/SHRINCSParams.sol";
import {IShrincsWallet} from "../../../contracts/shrincs/interfaces/IShrincsWallet.sol";
import {ShrincsWalletCodec as Codec} from "../../../contracts/shrincs/ShrincsWalletCodec.sol";
import {ShrincsWalletTest} from "../ShrincsWallet.t.sol";

/// @dev Behavior tests for the internal `_checkErc1271Signature` (via `exposed_checkErc1271Signature`),
///      which returns the discriminated `Erc1271ValidationResult` over the fixed-layout envelope. Order of
///      checks: length → envelope header → ECDSA-recover-vs-owner → zero hash → stateless
///      SHRINCS against the dedicated ERC-1271 verifier key. The ECDSA half is an AND-gate failsafe,
///      so a valid stateless half alone is never enough.
contract ShrincsWallet__checkErc1271Signature is ShrincsWalletTest {
    bytes32 internal constant HASH = keccak256("erc1271-internal-message");

    // Absolute envelope offsets of the fields the tamper tests flip. Every term is a codec or
    // `StatelessLayout` constant: nothing about the layout is restated here.
    uint256 internal constant PK_OFF = Codec.ERC1271_PAYLOAD_OFF;
    uint256 internal constant PK_SEED_OFF = PK_OFF + StatelessLayout.PK_SEED_OFFSET;
    uint256 internal constant FORS_OFF = PK_OFF + StatelessLayout.PK_LEN;
    uint256 internal constant FORS_COUNTER_OFF = FORS_OFF + StatelessLayout.FORS_COUNTER_OFFSET;
    uint256 internal constant FORS_LEAF0_OFF = FORS_OFF + StatelessLayout.FORS_ENTRIES_OFFSET;
    uint256 internal constant FORS_AUTH0_OFF = FORS_LEAF0_OFF + SHRINCSParams.HASH_LEN;
    uint256 internal constant HT_OFF = FORS_OFF + StatelessLayout.FORS_LEN;
    uint256 internal constant HT_CHAIN0_OFF = HT_OFF + StatelessLayout.LAYER_CHAINS_OFFSET;
    uint256 internal constant HT_AUTH0_OFF = HT_OFF + StatelessLayout.LAYER_AUTH_PATH_OFFSET;

    // Solady `Ownable` owner slot.
    bytes32 internal constant OWNER_SLOT = bytes32(uint256(0xffffffffffffffffffffffffffffffffffffffffffffffffffffffff74873927));

    function _result(bytes32 hash, bytes memory blob) internal view returns (IShrincsWallet.Erc1271ValidationResult) {
        return wallet.exposed_checkErc1271Signature(hash, blob);
    }

    function _assertResult(bytes32 hash, bytes memory blob, IShrincsWallet.Erc1271ValidationResult expected)
        internal
        view
    {
        assertEq(uint8(_result(hash, blob)), uint8(expected));
    }

    /// @dev A header-valid envelope with an empty (all-zero) SHRINCS payload.
    function _zeroPayloadBlob(bytes memory ecdsaSig) internal pure returns (bytes memory) {
        return abi.encodePacked(
            Codec.ERC1271_MAGIC,
            Codec.ERC1271_VERSION,
            SHRINCSParams.PROFILE_ID,
            ecdsaSig,
            new bytes(StatelessLayout.PAYLOAD_LEN)
        );
    }

    /// @dev Signs the dedicated-key ERC-1271 stateless message under an arbitrary context.
    function _signErc1271Ctx(SHRINCS.ActionContext memory ctx) internal returns (bytes memory) {
        bytes memory message = abi.encodePacked(
            SHRINCS.statelessRawMessageHash(
                erc1271Commitment, SHRINCS.statelessActionMessageHash(erc1271Commitment, ctx)
            )
        );
        return _signStatelessRaw(erc1271Key, erc1271Pk, message);
    }

    /// @dev Signs a valid blob, proves it is `Ok`, flips one byte at `at`, and asserts the
    ///      tampered blob fails the SHRINCS half (header and ECDSA untouched).
    function _assertTamperRejected(uint256 at) internal {
        bytes memory blob = _erc1271Blob(HASH);
        _assertResult(HASH, blob, IShrincsWallet.Erc1271ValidationResult.Ok);
        blob[at] ^= 0x01;
        _assertResult(HASH, blob, IShrincsWallet.Erc1271ValidationResult.InvalidShrincsSignature);
    }

    function test_checkErc1271_ok() public {
        _assertResult(HASH, _erc1271Blob(HASH), IShrincsWallet.Erc1271ValidationResult.Ok);
    }

    /// @dev The verified context tracks the LIVE nonce: a blob signed after the nonce moved is Ok.
    function test_checkErc1271_ok_afterNonceAndResign() public {
        wallet.harness_setNonce(wallet.actionNonce() + 7);
        _assertResult(HASH, _erc1271Blob(HASH), IShrincsWallet.Erc1271ValidationResult.Ok);
    }

    function test_checkErc1271_badSignatureLength() public view {
        // Any length other than ERC1271_TOTAL_LEN.
        _assertResult(HASH, hex"1234", IShrincsWallet.Erc1271ValidationResult.BadSignatureLength);
    }

    function test_checkErc1271_badSignatureLength_empty() public view {
        _assertResult(HASH, "", IShrincsWallet.Erc1271ValidationResult.BadSignatureLength);
    }

    function test_checkErc1271_badSignatureLength_oneByteShort() public view {
        bytes memory blob = _zeroPayloadBlob(_ownerEcdsa(HASH));
        assembly {
            mstore(blob, sub(mload(blob), 1))
        }
        _assertResult(HASH, blob, IShrincsWallet.Erc1271ValidationResult.BadSignatureLength);
    }

    function test_checkErc1271_badSignatureLength_trailingByte() public view {
        bytes memory blob = abi.encodePacked(_zeroPayloadBlob(_ownerEcdsa(HASH)), bytes1(0));
        _assertResult(HASH, blob, IShrincsWallet.Erc1271ValidationResult.BadSignatureLength);
    }

    /// @dev The legacy ABI blob of a VALID signature (91,840 bytes on 256s) is rejected at the
    ///      length check — it is never parsed.
    function test_checkErc1271_badSignatureLength_legacyAbiBlob() public {
        bytes memory legacy = _legacyErc1271Blob(HASH);
        assertEq(legacy.length, LEGACY_ERC1271_ABI_LEN, "legacy 256s ABI blob size");
        _assertResult(HASH, legacy, IShrincsWallet.Erc1271ValidationResult.BadSignatureLength);
    }

    function test_checkErc1271_malformed_wrongMagic() public view {
        bytes memory blob = _zeroPayloadBlob(_ownerEcdsa(HASH));
        blob[0] ^= 0x01;
        _assertResult(HASH, blob, IShrincsWallet.Erc1271ValidationResult.MalformedErc1271Payload);
    }

    function test_checkErc1271_malformed_wrongVersion() public view {
        bytes memory blob = _zeroPayloadBlob(_ownerEcdsa(HASH));
        blob[Codec.ERC1271_VERSION_OFF] = 0x02;
        _assertResult(HASH, blob, IShrincsWallet.Erc1271ValidationResult.MalformedErc1271Payload);
    }

    function test_checkErc1271_malformed_wrongProfile() public view {
        bytes memory blob = _zeroPayloadBlob(_ownerEcdsa(HASH));
        blob[Codec.ERC1271_PROFILE_OFF] ^= 0x01;
        _assertResult(HASH, blob, IShrincsWallet.Erc1271ValidationResult.MalformedErc1271Payload);
    }

    /// @dev A legacy ABI blob truncated to exactly the envelope length passes the length check
    ///      but fails the header (its first word is a tail offset): no legacy fallback.
    function test_checkErc1271_malformed_legacyAbiTruncatedToEnvelopeLength() public {
        bytes memory legacy = _legacyErc1271Blob(HASH);
        uint256 envelopeLen = Codec.ERC1271_TOTAL_LEN;
        assembly {
            mstore(legacy, envelopeLen)
        }
        assertEq(legacy.length, Codec.ERC1271_TOTAL_LEN);
        _assertResult(HASH, legacy, IShrincsWallet.Erc1271ValidationResult.MalformedErc1271Payload);
    }

    /// @dev A short legacy-shaped blob zero-padded to exactly the envelope length: same outcome.
    function test_checkErc1271_malformed_legacyAbiPaddedToEnvelopeLength() public view {
        bytes memory legacyHead = abi.encode(erc1271Pk, new bytes(0), _ownerEcdsa(HASH));
        bytes memory padded = abi.encodePacked(
            legacyHead, new bytes(Codec.ERC1271_TOTAL_LEN - legacyHead.length)
        );
        _assertResult(HASH, padded, IShrincsWallet.Erc1271ValidationResult.MalformedErc1271Payload);
    }

    function test_checkErc1271_invalidEcdsa_wrongSigner() public {
        // Stateless half structurally present but ECDSA recovers a non-owner ⇒ fails at the gate.
        (, uint256 wrongPk) = makeAddrAndKey("wrongSigner");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(wrongPk, wallet.quipSignedHashEcdsaTarget(HASH));
        bytes memory blob = _zeroPayloadBlob(abi.encodePacked(r, s, v));
        _assertResult(HASH, blob, IShrincsWallet.Erc1271ValidationResult.InvalidEcdsaSignature);
    }

    function test_checkErc1271_invalidEcdsa_unrecoverable() public view {
        // A 65-byte but garbage ECDSA signature recovers address(0) ⇒ rejected before SHRINCS.
        bytes memory blob = _zeroPayloadBlob(new bytes(Codec.ERC1271_ECDSA_LEN));
        _assertResult(HASH, blob, IShrincsWallet.Erc1271ValidationResult.InvalidEcdsaSignature);
    }

    /// @dev Owner signed a different hash: the ECDSA target binds `hash`.
    function test_checkErc1271_invalidEcdsa_ownerSignedOtherHash() public view {
        bytes memory blob = _zeroPayloadBlob(_ownerEcdsa(keccak256("other")));
        _assertResult(HASH, blob, IShrincsWallet.Erc1271ValidationResult.InvalidEcdsaSignature);
    }

    /// @dev A zero `owner()` never matches: an unrecoverable ECDSA half recovers address(0),
    ///      which the gate rejects explicitly rather than comparing equal.
    function test_checkErc1271_invalidEcdsa_zeroOwner() public {
        vm.store(address(wallet), OWNER_SLOT, bytes32(0));
        assertEq(wallet.owner(), address(0));
        bytes memory blob = _zeroPayloadBlob(new bytes(Codec.ERC1271_ECDSA_LEN));
        _assertResult(HASH, blob, IShrincsWallet.Erc1271ValidationResult.InvalidEcdsaSignature);
    }

    /// @dev Non-canonical v (not 27/28) does not recover the owner.
    function test_checkErc1271_invalidEcdsa_badV() public view {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(OWNER_PK, wallet.quipSignedHashEcdsaTarget(HASH));
        bytes memory blob = _zeroPayloadBlob(abi.encodePacked(r, s, v + 2));
        _assertResult(HASH, blob, IShrincsWallet.Erc1271ValidationResult.InvalidEcdsaSignature);
    }

    function test_checkErc1271_invalidShrincs() public view {
        // Owner ECDSA valid, but an empty (all-zero) stateless payload fails SHRINCS verification.
        bytes memory blob = _zeroPayloadBlob(_ownerEcdsa(HASH));
        _assertResult(HASH, blob, IShrincsWallet.Erc1271ValidationResult.InvalidShrincsSignature);
    }

    function test_checkErc1271_invalidShrincs_wrongHash() public {
        // The signature is bound to `HASH`; presenting it under a different message (with a
        // matching owner ECDSA over that other message) fails SHRINCS.
        bytes32 otherHash = keccak256("a-different-message");
        bytes memory blob = _erc1271Envelope(erc1271Pk, _signErc1271(HASH), _ownerEcdsa(otherHash));
        _assertResult(otherHash, blob, IShrincsWallet.Erc1271ValidationResult.InvalidShrincsSignature);
    }

    function test_checkErc1271_invalidShrincs_zeroHash() public {
        bytes memory blob = _erc1271Envelope(erc1271Pk, _signErc1271(bytes32(0)), _ownerEcdsa(bytes32(0)));
        _assertResult(bytes32(0), blob, IShrincsWallet.Erc1271ValidationResult.InvalidShrincsSignature);
    }

    function test_checkErc1271_invalidShrincs_nonceChanged() public {
        bytes memory blob = _erc1271Blob(HASH);
        wallet.harness_setNonce(wallet.actionNonce() + 1);
        _assertResult(HASH, blob, IShrincsWallet.Erc1271ValidationResult.InvalidShrincsSignature);
    }

    function test_checkErc1271_invalidShrincs_keyVersionChanged() public {
        bytes memory blob = _erc1271Blob(HASH);
        wallet.harness_setKeyVersion(wallet.keyVersion() + 1);
        _assertResult(HASH, blob, IShrincsWallet.Erc1271ValidationResult.InvalidShrincsSignature);
    }

    /// @dev A valid stateless signature by a DIFFERENT bundle (the main key's stateless half)
    ///      over the same canonical message: its commitment is not the installed 1271 key.
    function test_checkErc1271_invalidShrincs_wrongCommitment() public {
        SHRINCS.ActionContext memory ctx = _actionContext(Codec.ACTION_ERC1271, HASH);
        bytes memory message = abi.encodePacked(
            SHRINCS.statelessRawMessageHash(mainCommitment, SHRINCS.statelessActionMessageHash(mainCommitment, ctx))
        );
        bytes memory sig = _signStatelessRaw(mainKey, mainPk, message);
        bytes memory blob = _erc1271Envelope(mainPk, sig, _ownerEcdsa(HASH));
        _assertResult(HASH, blob, IShrincsWallet.Erc1271ValidationResult.InvalidShrincsSignature);
    }

    function test_checkErc1271_invalidShrincs_tamperedPkField() public {
        _assertTamperRejected(PK_SEED_OFF);
    }

    function test_checkErc1271_invalidShrincs_tamperedForsRandomizer() public {
        _assertTamperRejected(FORS_OFF);
    }

    function test_checkErc1271_invalidShrincs_tamperedForsCounter() public {
        _assertTamperRejected(FORS_COUNTER_OFF + 3);
    }

    function test_checkErc1271_invalidShrincs_tamperedForsLeaf() public {
        _assertTamperRejected(FORS_LEAF0_OFF);
    }

    function test_checkErc1271_invalidShrincs_tamperedForsAuthPath() public {
        _assertTamperRejected(FORS_AUTH0_OFF);
    }

    function test_checkErc1271_invalidShrincs_tamperedWotsPkHash() public {
        _assertTamperRejected(HT_OFF);
    }

    function test_checkErc1271_invalidShrincs_tamperedWotsChain() public {
        _assertTamperRejected(HT_CHAIN0_OFF);
    }

    function test_checkErc1271_invalidShrincs_tamperedWotsAuthPath() public {
        _assertTamperRejected(HT_AUTH0_OFF);
    }

    /// @dev Signed for this wallet on another chain: the owner re-signs the ECDSA half under the
    ///      live chain, so only the SHRINCS domain separator (chainId) differs.
    function test_checkErc1271_invalidShrincs_wrongChainDomain() public {
        bytes memory sig = _signErc1271(HASH);
        vm.chainId(CHAIN_ID + 1);
        bytes memory blob = _erc1271Envelope(erc1271Pk, sig, _ownerEcdsa(HASH));
        _assertResult(HASH, blob, IShrincsWallet.Erc1271ValidationResult.InvalidShrincsSignature);
    }

    /// @dev Signed by the right key and nonce but under another wallet's domain separator.
    function test_checkErc1271_invalidShrincs_wrongWalletDomain() public {
        SHRINCS.ActionContext memory ctx = _actionContext(Codec.ACTION_ERC1271, HASH);
        ctx.domainSeparator =
            keccak256(abi.encodePacked(Codec.DOMAIN_TAG, block.chainid, uint256(uint160(makeAddr("otherWallet")))));
        bytes memory blob = _erc1271Envelope(erc1271Pk, _signErc1271Ctx(ctx), _ownerEcdsa(HASH));
        _assertResult(HASH, blob, IShrincsWallet.Erc1271ValidationResult.InvalidShrincsSignature);
    }

    /// @dev Signed under another action type (e.g. a stateless execute-shaped context).
    function test_checkErc1271_invalidShrincs_wrongActionType() public {
        SHRINCS.ActionContext memory ctx = _actionContext(Codec.ACTION_EXECUTE, HASH);
        bytes memory blob = _erc1271Envelope(erc1271Pk, _signErc1271Ctx(ctx), _ownerEcdsa(HASH));
        _assertResult(HASH, blob, IShrincsWallet.Erc1271ValidationResult.InvalidShrincsSignature);
    }
}

/// @dev Fuzz tests for `_checkErc1271Signature`. One valid envelope is signed in `setUp` (signing
///      is the expensive step) and every run mutates a copy of it. The region a mutation lands in
///      decides which check must catch it, so each test also pins the ORDER of the checks.
contract ShrincsWallet__checkErc1271SignatureFuzz is ShrincsWalletTest {
    bytes32 internal constant HASH = keccak256("erc1271-internal-fuzz-message");

    bytes internal validBlob;

    function setUp() public override {
        super.setUp();
        validBlob = _erc1271Blob(HASH);
    }

    function test_setUp() public view override {
        super.test_setUp();
        assertEq(validBlob.length, Codec.ERC1271_TOTAL_LEN, "fixture: exact envelope length");
        _assertResult(validBlob, IShrincsWallet.Erc1271ValidationResult.Ok);
    }

    function _assertResult(bytes memory blob, IShrincsWallet.Erc1271ValidationResult expected) internal view {
        assertEq(uint8(wallet.exposed_checkErc1271Signature(HASH, blob)), uint8(expected));
    }

    /// @dev A copy of the valid envelope with one bit flipped at byte `at`.
    function _flipped(uint256 at, uint8 bit) internal view returns (bytes memory blob) {
        blob = validBlob;
        blob[at] ^= bytes1(uint8(1) << (bit % 8));
    }

    /// @dev Any single flipped bit in the header (magic, version, profile id) is a malformed envelope.
    function testFuzz_checkErc1271_malformed_anyHeaderBitFlipped(uint256 at, uint8 bit) public view {
        at = bound(at, 0, Codec.ERC1271_HEADER_LEN - 1);
        _assertResult(_flipped(at, bit), IShrincsWallet.Erc1271ValidationResult.MalformedErc1271Payload);
    }

    /// @dev Any single flipped bit in the owner ECDSA half fails the ECDSA gate, before SHRINCS.
    function testFuzz_checkErc1271_invalidEcdsa_anyEcdsaBitFlipped(uint256 at, uint8 bit) public view {
        at = bound(at, Codec.ERC1271_ECDSA_OFF, Codec.ERC1271_PAYLOAD_OFF - 1);
        _assertResult(_flipped(at, bit), IShrincsWallet.Erc1271ValidationResult.InvalidEcdsaSignature);
    }

    /// @dev Any single flipped bit anywhere in `PK ‖ PQ` fails the SHRINCS half: no byte of the
    ///      payload is unauthenticated.
    function testFuzz_checkErc1271_invalidShrincs_anyPayloadBitFlipped(uint256 at, uint8 bit) public view {
        at = bound(at, Codec.ERC1271_PAYLOAD_OFF, Codec.ERC1271_TOTAL_LEN - 1);
        _assertResult(_flipped(at, bit), IShrincsWallet.Erc1271ValidationResult.InvalidShrincsSignature);
    }

    /// @dev Any length other than the exact envelope length is rejected at the length check,
    ///      whatever the bytes are (here: a prefix or zero-extension of a valid envelope).
    function testFuzz_checkErc1271_badSignatureLength_anyOtherLength(uint256 newLen) public view {
        newLen = bound(newLen, 0, 2 * Codec.ERC1271_TOTAL_LEN);
        vm.assume(newLen != Codec.ERC1271_TOTAL_LEN);
        bytes memory blob = abi.encodePacked(validBlob, new bytes(Codec.ERC1271_TOTAL_LEN));
        assembly {
            mstore(blob, newLen)
        }
        _assertResult(blob, IShrincsWallet.Erc1271ValidationResult.BadSignatureLength);
    }

    /// @dev A valid envelope approves exactly one hash: under any other hash the owner ECDSA half
    ///      (which binds the hash) no longer recovers the owner.
    function testFuzz_checkErc1271_invalidEcdsa_anyOtherHash(bytes32 otherHash) public view {
        vm.assume(otherHash != HASH);
        assertEq(
            uint8(wallet.exposed_checkErc1271Signature(otherHash, validBlob)),
            uint8(IShrincsWallet.Erc1271ValidationResult.InvalidEcdsaSignature)
        );
    }
}
