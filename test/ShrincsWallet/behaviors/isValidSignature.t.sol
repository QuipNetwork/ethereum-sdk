// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {StatelessLayout} from "@quip.network/hashsigs-solidity-0.4.0/contracts/StatelessLayout.sol";
import {SHRINCS} from "@quip.network/hashsigs-solidity-0.4.0/contracts/SHRINCS.sol";
import {SHRINCSVerifier} from "@quip.network/hashsigs-solidity-0.4.0/contracts/SHRINCSVerifier.sol";
import {UXMSS} from "@quip.network/hashsigs-solidity-0.4.0/contracts/UXMSS.sol";
import {HashSuite} from "shrincs-hash/HashSuite.sol";
import {SHRINCSParams} from "shrincs-profile/SHRINCSParams.sol";
import {IShrincsWallet} from "../../../contracts/shrincs/interfaces/IShrincsWallet.sol";
import {ShrincsWalletCodec as Codec} from "../../../contracts/shrincs/ShrincsWalletCodec.sol";
import {ShrincsWalletHarness} from "../../harness/ShrincsWalletHarness.sol";
import {ShrincsWalletTest} from "../ShrincsWallet.t.sol";
import {IERC1271} from "@openzeppelin-contracts-5.6.0-rc.1/interfaces/IERC1271.sol";

/// @dev Behavior tests for ERC-1271 `isValidSignature` / `debugIsValidSignature` over the fixed-layout
///      envelope. The length, header, ECDSA, and stateless-failure branches plus the full `Ok` path
///      (a live-signed ERC-1271 signature) are all exercised, as is the never-revert
///      property under STATICCALL and supersession by every kind of consumed wallet signature.
contract ShrincsWallet_isValidSignature is ShrincsWalletTest {
    bytes4 internal constant MAGIC = IERC1271.isValidSignature.selector;
    bytes4 internal constant FAIL = 0xffffffff;
    bytes32 internal constant HASH = keccak256("erc1271-message");

    /// @dev A header-valid envelope carrying `ecdsaSig` and the given SHRINCS payload.
    function _envelope(bytes memory ecdsaSig, bytes memory payload) internal pure returns (bytes memory) {
        return abi.encodePacked(
            Codec.ERC1271_MAGIC, Codec.ERC1271_VERSION, SHRINCSParams.PROFILE_ID, ecdsaSig, payload
        );
    }

    /// @dev `isValidSignature` through a raw STATICCALL, as a relying contract would make it.
    function _staticIsValid(bytes32 hash, bytes memory blob) internal view returns (bool ok, bytes4 result) {
        bytes memory ret;
        (ok, ret) = address(wallet).staticcall(abi.encodeCall(wallet.isValidSignature, (hash, blob)));
        if (ok) result = abi.decode(ret, (bytes4));
    }

    function test_isValidSignature_ok() public {
        bytes memory blob = _erc1271Blob(HASH);
        assertEq(blob.length, Codec.ERC1271_TOTAL_LEN, "envelope size");
        assertEq(wallet.isValidSignature(HASH, blob), MAGIC);
        assertEq(uint8(wallet.debugIsValidSignature(HASH, blob)), uint8(IShrincsWallet.Erc1271ValidationResult.Ok));
    }

    function test_isValidSignature_ok_underStaticcall() public {
        (bool ok, bytes4 result) = _staticIsValid(HASH, _erc1271Blob(HASH));
        assertTrue(ok, "view-safe under STATICCALL");
        assertEq(result, MAGIC);
    }

    /// @dev The stateless 1271 verify must actually leave the wallet: a valid blob staticcalls
    ///      the pinned verifier's `verifyStateless` with the commitment key and the
    ///      payload slice forwarded unchanged.
    function test_isValidSignature_delegatesToVerifier() public {
        bytes memory blob = _erc1271Blob(HASH);
        bytes memory payload = new bytes(StatelessLayout.PAYLOAD_LEN);
        for (uint256 i; i < payload.length; ++i) {
            payload[i] = blob[Codec.ERC1271_PAYLOAD_OFF + i];
        }
        bytes32 messageHash = SHRINCS.statelessActionMessageHash(
            erc1271Commitment, _actionContext(Codec.ACTION_ERC1271, HASH)
        );
        vm.expectCall(
            address(shrincsVerifier),
            abi.encodeCall(
                SHRINCSVerifier.verifyStateless,
                (abi.encodePacked(erc1271Commitment), messageHash, payload)
            )
        );
        assertEq(wallet.isValidSignature(HASH, blob), MAGIC, "valid through the external verifier");
    }

    /// @dev Intended supersession: the 1271 context binds the LIVE action nonce, so a blob dies
    ///      the moment any wallet signature is consumed — and a fresh re-sign is valid again.
    function test_isValidSignature_staleNonceRejected_freshResignOk() public {
        bytes memory blob = _erc1271Blob(HASH);
        assertEq(wallet.isValidSignature(HASH, blob), MAGIC, "fresh blob valid");

        // Any consumed wallet signature advances the nonce (stood in for by the harness setter).
        wallet.harness_setNonce(wallet.actionNonce() + 1);

        assertEq(wallet.isValidSignature(HASH, blob), FAIL, "blob superseded by the nonce advance");
        assertEq(
            uint8(wallet.debugIsValidSignature(HASH, blob)),
            uint8(IShrincsWallet.Erc1271ValidationResult.InvalidShrincsSignature)
        );

        // Re-signing against the new live nonce restores validity.
        assertEq(wallet.isValidSignature(HASH, _erc1271Blob(HASH)), MAGIC, "re-signed blob valid");
    }

    function test_isValidSignature_returnsFailureWhen_badLength() public view {
        assertEq(wallet.isValidSignature(HASH, hex"1234"), FAIL);
        assertEq(
            uint8(wallet.debugIsValidSignature(HASH, hex"1234")),
            uint8(IShrincsWallet.Erc1271ValidationResult.BadSignatureLength)
        );
    }

    /// @dev The legacy ABI encoding of a VALID signature is rejected by length, never parsed.
    function test_isValidSignature_returnsFailureWhen_legacyAbiBlob() public {
        bytes memory legacy = _legacyErc1271Blob(HASH);
        assertEq(wallet.isValidSignature(HASH, legacy), FAIL);
        assertEq(
            uint8(wallet.debugIsValidSignature(HASH, legacy)),
            uint8(IShrincsWallet.Erc1271ValidationResult.BadSignatureLength)
        );
    }

    function test_isValidSignature_returnsFailureWhen_invalidEcdsa() public {
        (, uint256 wrongPk) = makeAddrAndKey("wrongSigner");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(wrongPk, wallet.quipSignedHashEcdsaTarget(HASH));
        bytes memory blob =
            _envelope(abi.encodePacked(r, s, v), new bytes(StatelessLayout.PAYLOAD_LEN));

        assertEq(wallet.isValidSignature(HASH, blob), FAIL);
        assertEq(
            uint8(wallet.debugIsValidSignature(HASH, blob)),
            uint8(IShrincsWallet.Erc1271ValidationResult.InvalidEcdsaSignature)
        );
    }

    function test_isValidSignature_returnsFailureWhen_invalidShrincs() public view {
        // Owner ECDSA is valid, but the (all-zero) stateless payload fails SHRINCS verification.
        bytes memory blob = _envelope(_ownerEcdsa(HASH), new bytes(StatelessLayout.PAYLOAD_LEN));

        assertEq(wallet.isValidSignature(HASH, blob), FAIL);
        assertEq(
            uint8(wallet.debugIsValidSignature(HASH, blob)),
            uint8(IShrincsWallet.Erc1271ValidationResult.InvalidShrincsSignature)
        );
    }

    /// @dev A valid signature whose header is broken (magic) is rejected before ECDSA.
    function test_isValidSignature_returnsFailureWhen_topLevelMalformed() public {
        bytes memory blob = _erc1271Blob(HASH);
        blob[0] = 0x00;
        assertEq(wallet.isValidSignature(HASH, blob), FAIL);
        assertEq(
            uint8(wallet.debugIsValidSignature(HASH, blob)),
            uint8(IShrincsWallet.Erc1271ValidationResult.MalformedErc1271Payload)
        );
    }

    function test_isValidSignature_returnsFailureWhen_zeroHash() public {
        bytes memory blob = _erc1271Blob(bytes32(0));
        assertEq(wallet.isValidSignature(bytes32(0), blob), FAIL);
        assertEq(
            uint8(wallet.debugIsValidSignature(bytes32(0), blob)),
            uint8(IShrincsWallet.Erc1271ValidationResult.InvalidShrincsSignature)
        );
    }

    /* ───────────────────── never-revert (staticcall DoS resistance) ───────────────────── */

    /// @dev ERC-1271 never-revert property: a relying contract staticcalls `isValidSignature`, so
    ///      any revert is a denial of service on it. Adversarial blobs of every shape must return
    ///      the FAIL magic.
    function test_isValidSignature_neverReverts_onMalformedBlobs() public {
        _neverReverts(_fill(0x60, 0xff), "0x60 0xff (offsets wrap huge)");
        _neverReverts(_fill(0x100, 0xff), "0x100 0xff");
        _neverReverts(_fill(0x80, 0xff), "0x80 0xff (SDK client garbage)");
        _neverReverts(
            abi.encodePacked(bytes32(0), bytes32(0), bytes32(uint256(0x60)), bytes32(type(uint256).max)),
            "huge ecdsaSig length word"
        );
        _neverReverts(_pseudoRandom(0xc8, 0), "pseudo-random 0xc8");
        _neverReverts(_fill(Codec.ERC1271_TOTAL_LEN, 0xff), "envelope length 0xff");
        _neverReverts(_envelope(_ownerEcdsa(HASH), _fill(StatelessLayout.PAYLOAD_LEN, 0xff)), "0xff payload");
    }

    /// @dev The legacy ABI blob with corrupted NESTED tail offsets — the shape that needed the
    ///      old `erc1271Envelope` containment — now fails at the length check without reverting.
    function test_isValidSignature_neverReverts_onCorruptedNestedOffsets() public {
        bytes memory legit = _legacyErc1271Blob(HASH);
        uint256 pkOff = _word(legit, 0x00);
        uint256 sigOff = _word(legit, 0x20);

        bytes memory pkCorrupt = _clone(legit);
        _setWord(pkCorrupt, pkOff, 1 << 64);
        _neverRevertsWith(pkCorrupt, IShrincsWallet.Erc1271ValidationResult.BadSignatureLength, "nested pk offset");

        bytes memory sigCorrupt = _clone(legit);
        _setWord(sigCorrupt, sigOff + 0x20, 1 << 64);
        _neverRevertsWith(sigCorrupt, IShrincsWallet.Erc1271ValidationResult.BadSignatureLength, "nested sig offset");
    }

    /// @dev Truncating or extending a REAL signed envelope by any amount never reverts.
    function test_isValidSignature_neverReverts_onResizedValidBlob() public {
        bytes memory blob = _erc1271Blob(HASH);
        uint256[5] memory cuts = [uint256(0), 4, 37, 102, Codec.ERC1271_TOTAL_LEN - 1];
        for (uint256 i; i < cuts.length; ++i) {
            bytes memory cut = _clone(blob);
            uint256 n = cuts[i];
            assembly {
                mstore(cut, n)
            }
            _neverRevertsWith(cut, IShrincsWallet.Erc1271ValidationResult.BadSignatureLength, "truncated");
        }
        _neverRevertsWith(
            abi.encodePacked(blob, bytes1(0)), IShrincsWallet.Erc1271ValidationResult.BadSignatureLength, "trailing byte"
        );
    }

    /* ─────────────────────────────── supersession ─────────────────────────────── */

    function test_isValidSignature_supersededBy_userOpExecute() public {
        bytes memory blob = _erc1271Blob(HASH);
        assertEq(wallet.isValidSignature(HASH, blob), MAGIC, "valid before");
        bytes32 userOpHash = keccak256("supersede-userop");
        bytes memory opSig = _userOpBlob(_signErc4337(userOpHash, 1), userOpHash);
        vm.prank(ENTRY_POINT);
        assertEq(wallet.validateUserOp(_makeUserOp(opSig), userOpHash, 0), 0, "userOp validated");
        assertEq(wallet.isValidSignature(HASH, blob), FAIL, "superseded");
    }

    function test_isValidSignature_supersededBy_rotateKey() public {
        bytes memory blob = _erc1271Blob(HASH);
        assertEq(wallet.isValidSignature(HASH, blob), MAGIC, "valid before");
        (SHRINCS.StatefulRotationTarget memory t, bytes32 nextCommitment) =
            _makeStatefulRotationTarget("supersede-rotate-key");
        SHRINCS.Signature memory sig =
            _signStatefulAction(Codec.ACTION_ROTATE_KEY, Codec.rotateKeyPayloadHash(nextCommitment), 1);
        vm.prank(OWNER);
        wallet.rotateKey(_mainPk(), sig, t);
        assertEq(wallet.isValidSignature(HASH, blob), FAIL, "superseded");
    }

    function test_isValidSignature_supersededBy_setErc1271Key() public {
        bytes memory blob = _erc1271Blob(HASH);
        assertEq(wallet.isValidSignature(HASH, blob), MAGIC, "valid before");
        SHRINCS.PublicKey memory newPk = _freshErc1271Pk("supersede-set-erc1271");
        SHRINCS.Signature memory sig = _signStatefulAction(
            Codec.ACTION_SET_ERC1271_KEY,
            Codec.setErc1271KeyPayloadHash(_commitment32(newPk), HashSuite.HASH_SUITE_ID),
            1
        );
        vm.prank(OWNER);
        wallet.setErc1271Key(_mainPk(), sig, newPk, HashSuite.HASH_SUITE_ID);
        assertEq(wallet.isValidSignature(HASH, blob), FAIL, "superseded");
    }

    function test_isValidSignature_supersededBy_upgradeToAndCall() public {
        bytes memory blob = _erc1271Blob(HASH);
        assertEq(wallet.isValidSignature(HASH, blob), MAGIC, "valid before");
        ShrincsWalletHarness impl = new ShrincsWalletHarness(payable(address(factory)), address(shrincsVerifier));
        vm.prank(ADMIN);
        factory.vetImplementation(address(impl));
        SHRINCS.Signature memory sig =
            _signStatefulAction(Codec.ACTION_UPGRADE, Codec.upgradePayloadHash(address(impl), false, keccak256("")), 1);
        bytes memory data =
            abi.encode(_mainPk(), sig, false, bytes(""), wallet.actionNonce(), _probeVectorFor(address(impl)));
        vm.prank(OWNER);
        wallet.upgradeToAndCall(address(impl), data);
        assertEq(wallet.isValidSignature(HASH, blob), FAIL, "superseded");
    }

    /* ─────────────────────────────────── fuzz ─────────────────────────────────── */

    function testFuzz_isValidSignature_neverReverts_onRandomBytes(bytes calldata blob) public view {
        (bool ok, bytes4 result) = _staticIsValid(HASH, blob);
        assertTrue(ok, "no revert");
        assertEq(result, FAIL);
    }

    /// @dev Header-valid envelope of any length around the envelope size, owner ECDSA valid.
    function testFuzz_isValidSignature_neverReverts_onResizedEnvelope(uint256 newLen) public view {
        newLen = bound(newLen, 0, Codec.ERC1271_TOTAL_LEN + 64);
        bytes memory full = _envelope(_ownerEcdsa(HASH), _pseudoRandom(StatelessLayout.PAYLOAD_LEN + 64, 1));
        assembly {
            mstore(full, newLen)
        }
        (bool ok, bytes4 result) = _staticIsValid(HASH, full);
        assertTrue(ok, "no revert");
        assertEq(result, FAIL);
    }

    /// @dev The installed bundle and a valid owner ECDSA, with a random PQ part: the verifier is
    ///      reached with garbage FORS/hypertree internals and must still answer FAIL.
    function testFuzz_isValidSignature_neverReverts_onRandomPqPart(uint256 seed) public view {
        bytes memory payload = abi.encodePacked(
            erc1271Pk.statefulPublicKey,
            erc1271Pk.publicKeyCommitment,
            erc1271Pk.pkSeed,
            erc1271Pk.hypertreeRoot,
            _pseudoRandom(StatelessLayout.PAYLOAD_LEN - StatelessLayout.PK_LEN, seed)
        );
        (bool ok, bytes4 result) = _staticIsValid(HASH, _envelope(_ownerEcdsa(HASH), payload));
        assertTrue(ok, "no revert");
        assertEq(result, FAIL);
    }

    /* ─────────────────────────────────── helpers ─────────────────────────────────── */

    /// @dev Asserts `isValidSignature` returns FAIL for `blob` WITHOUT reverting (try/catch turns a
    ///      revert into a test failure rather than aborting the whole run).
    function _neverReverts(bytes memory blob, string memory name) internal view {
        try wallet.isValidSignature(HASH, blob) returns (bytes4 result) {
            assertEq(result, FAIL, name);
        } catch {
            revert(string.concat("isValidSignature reverted on adversarial blob: ", name));
        }
    }

    function _neverRevertsWith(
        bytes memory blob,
        IShrincsWallet.Erc1271ValidationResult expected,
        string memory name
    ) internal view {
        _neverReverts(blob, name);
        assertEq(uint8(wallet.debugIsValidSignature(HASH, blob)), uint8(expected), name);
    }

    function _fill(uint256 n, uint8 b) internal pure returns (bytes memory out) {
        out = new bytes(n);
        for (uint256 i; i < n; ++i) {
            out[i] = bytes1(b);
        }
    }

    /// @dev `n` deterministic pseudo-random bytes from `seed` (keccak counter stream).
    function _pseudoRandom(uint256 n, uint256 seed) internal pure returns (bytes memory out) {
        out = new bytes(n);
        for (uint256 i; i < n; i += 32) {
            bytes32 w = keccak256(abi.encode(seed, i));
            for (uint256 j; j < 32 && i + j < n; ++j) {
                out[i + j] = w[j];
            }
        }
    }

    function _word(bytes memory b, uint256 at) internal pure returns (uint256 w) {
        assembly {
            w := mload(add(add(b, 0x20), at))
        }
    }

    function _setWord(bytes memory b, uint256 at, uint256 w) internal pure {
        assembly {
            mstore(add(add(b, 0x20), at), w)
        }
    }

    function _clone(bytes memory b) internal pure returns (bytes memory) {
        return abi.encodePacked(b);
    }
}
