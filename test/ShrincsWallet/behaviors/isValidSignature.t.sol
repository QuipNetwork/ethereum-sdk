// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {SHRINCS} from "@quip.network/hashsigs-solidity-0.2.0/contracts/SHRINCS.sol";
import {SPHINCSPlusC} from "@quip.network/hashsigs-solidity-0.2.0/contracts/SPHINCSPlusC.sol";
import {SHRINCSVerifier} from "@quip.network/hashsigs-solidity-0.2.0/contracts/SHRINCSVerifier.sol";
import {UXMSS} from "@quip.network/hashsigs-solidity-0.2.0/contracts/UXMSS.sol";
import {HashSuite} from "shrincs-hash/HashSuite.sol";
import {SHRINCSParams} from "shrincs-profile/SHRINCSParams.sol";
import {IShrincsWallet} from "../../../contracts/shrincs/interfaces/IShrincsWallet.sol";
import {ShrincsWalletTest} from "../ShrincsWallet.t.sol";

/// @dev Behavior tests for ERC-1271 `isValidSignature` / `debugIsValidSignature`. The length,
///      ECDSA, and stateless-failure branches plus the full `Ok` path (a live-signed stateless
///      ERC-1271 signature) are all exercised. The ECDSA half is owner-controlled.
contract ShrincsWallet_isValidSignature is ShrincsWalletTest {
    bytes4 internal constant MAGIC = 0x1626ba7e;
    bytes4 internal constant FAIL = 0xffffffff;
    bytes32 internal constant HASH = keccak256("erc1271-message");

    /// @dev Encodes the ERC-1271 `(PublicKey, StatelessSignature, bytes ecdsaSig)` blob.
    function _blob(SHRINCS.PublicKey memory pk, SPHINCSPlusC.Signature memory sig, bytes memory ecdsaSig)
        internal
        pure
        returns (bytes memory)
    {
        return abi.encode(pk, sig, ecdsaSig);
    }

    function test_isValidSignature_revertsWhen_badLength() public view {
        assertEq(wallet.isValidSignature(HASH, hex"1234"), FAIL);
        assertEq(
            uint8(wallet.debugIsValidSignature(HASH, hex"1234")),
            uint8(IShrincsWallet.Erc1271ValidationResult.BadSignatureLength)
        );
    }

    function test_isValidSignature_revertsWhen_invalidEcdsa() public {
        (, uint256 wrongPk) = makeAddrAndKey("wrongSigner");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(wrongPk, wallet.quipSignedHashEcdsaTarget(HASH));
        SPHINCSPlusC.Signature memory emptySig;
        bytes memory blob = _blob(erc1271Pk, emptySig, abi.encodePacked(r, s, v));

        assertEq(wallet.isValidSignature(HASH, blob), FAIL);
        assertEq(
            uint8(wallet.debugIsValidSignature(HASH, blob)),
            uint8(IShrincsWallet.Erc1271ValidationResult.InvalidEcdsaSignature)
        );
    }

    function test_isValidSignature_revertsWhen_invalidShrincs() public {
        // Owner ECDSA is valid, but the (empty) stateless signature fails SHRINCS verification.
        SPHINCSPlusC.Signature memory emptySig;
        bytes memory blob = _blob(erc1271Pk, emptySig, _ownerEcdsa(HASH));

        assertEq(wallet.isValidSignature(HASH, blob), FAIL);
        assertEq(
            uint8(wallet.debugIsValidSignature(HASH, blob)),
            uint8(IShrincsWallet.Erc1271ValidationResult.InvalidShrincsSignature)
        );
    }

    function test_isValidSignature_revertsWhen_topLevelMalformed() public {
        SPHINCSPlusC.Signature memory sig = _signErc1271(HASH);
        bytes memory blob = _blob(erc1271Pk, sig, _ownerEcdsa(HASH));
        bytes memory cut = new bytes(0x60);
        for (uint256 i; i < 0x60; ++i) {
            cut[i] = blob[i];
        }
        assertEq(wallet.isValidSignature(HASH, cut), FAIL);
        assertEq(
            uint8(wallet.debugIsValidSignature(HASH, cut)),
            uint8(IShrincsWallet.Erc1271ValidationResult.MalformedErc1271Payload)
        );
    }

    /// @dev ERC-1271 never-revert property (staticcall DoS resistance): a relying contract
    ///      staticcalls `isValidSignature`, so any revert is a denial of service on it. Adversarial
    ///      blobs whose ABI tail offsets point out of bounds — which the codec's `pw8` bounds-check
    ///      reverts on — must instead return the FAIL magic through the ERC-1271 path. The adversary
    ///      cannot forge the owner ECDSA, so it short-circuits before the (revert-prone) nested
    ///      SHRINCS reads; only the top-level decode is reached, and it must not revert.
    function test_isValidSignature_neverReverts_onMalformedBlobs() public {
        _neverReverts(_fill(0x60, 0xff), "0x60 0xff (offsets wrap huge)");
        _neverReverts(_fill(0x100, 0xff), "0x100 0xff");
        _neverReverts(_fill(0x80, 0xff), "0x80 0xff (SDK client garbage)");
        _neverReverts(
            abi.encodePacked(bytes32(0), bytes32(0), bytes32(uint256(0x60)), bytes32(type(uint256).max)),
            "huge ecdsaSig length word"
        );
        _neverReverts(_pseudoRandom(0xc8), "pseudo-random 0xc8");
    }

    /// @dev Asserts `isValidSignature` returns FAIL for `blob` WITHOUT reverting (try/catch turns a
    ///      revert into a test failure rather than aborting the whole run).
    function _neverReverts(bytes memory blob, string memory name) internal view {
        try wallet.isValidSignature(HASH, blob) returns (bytes4 result) {
            assertEq(result, FAIL, name);
        } catch {
            revert(string.concat("isValidSignature reverted on adversarial blob: ", name));
        }
    }

    function _fill(uint256 n, uint8 b) internal pure returns (bytes memory out) {
        out = new bytes(n);
        for (uint256 i; i < n; ++i) {
            out[i] = bytes1(b);
        }
    }

    function _pseudoRandom(uint256 n) internal pure returns (bytes memory out) {
        out = new bytes(n);
        for (uint256 i; i < n; ++i) {
            out[i] = bytes1(uint8((i * 131 + 17) & 0xff));
        }
    }

    function test_isValidSignature_ok() public {
        SPHINCSPlusC.Signature memory sig = _signErc1271(HASH);
        bytes memory blob = _blob(erc1271Pk, sig, _ownerEcdsa(HASH));
        assertEq(wallet.isValidSignature(HASH, blob), MAGIC);
        assertEq(uint8(wallet.debugIsValidSignature(HASH, blob)), uint8(IShrincsWallet.Erc1271ValidationResult.Ok));
    }

    function test_isValidSignature_revertsWhen_zeroHash() public {
        SPHINCSPlusC.Signature memory sig = _signErc1271(bytes32(0));
        bytes memory blob = _blob(erc1271Pk, sig, _ownerEcdsa(bytes32(0)));
        assertEq(wallet.isValidSignature(bytes32(0), blob), FAIL);
        assertEq(
            uint8(wallet.debugIsValidSignature(bytes32(0), blob)),
            uint8(IShrincsWallet.Erc1271ValidationResult.InvalidShrincsSignature)
        );
    }

    /// @dev The stateless 1271 verify must actually leave the wallet: a valid blob staticcalls
    ///      the pinned verifier's `verifyStateless`.
    function test_isValidSignature_delegatesToVerifier() public {
        SPHINCSPlusC.Signature memory sig = _signErc1271(HASH);
        bytes memory blob = _blob(erc1271Pk, sig, _ownerEcdsa(HASH));
        vm.expectCall(
            address(shrincsVerifier), abi.encodeWithSelector(SHRINCSVerifier.verifyStateless.selector)
        );
        assertEq(wallet.isValidSignature(HASH, blob), MAGIC, "valid through the external verifier");
    }

    /// @dev Intended supersession: the 1271 context binds the LIVE action nonce, so a blob dies
    ///      the moment any wallet signature is consumed — and a fresh re-sign is valid again.
    function test_isValidSignature_staleNonceRejected_freshResignOk() public {
        SPHINCSPlusC.Signature memory sig = _signErc1271(HASH);
        bytes memory blob = _blob(erc1271Pk, sig, _ownerEcdsa(HASH));
        assertEq(wallet.isValidSignature(HASH, blob), MAGIC, "fresh blob valid");

        // Any consumed wallet signature advances the nonce (stood in for by the harness setter).
        wallet.harness_setNonce(wallet.actionNonce() + 1);

        assertEq(wallet.isValidSignature(HASH, blob), FAIL, "blob superseded by the nonce advance");
        assertEq(
            uint8(wallet.debugIsValidSignature(HASH, blob)),
            uint8(IShrincsWallet.Erc1271ValidationResult.InvalidShrincsSignature)
        );

        // Re-signing against the new live nonce restores validity.
        SPHINCSPlusC.Signature memory fresh = _signErc1271(HASH);
        bytes memory freshBlob = _blob(erc1271Pk, fresh, _ownerEcdsa(HASH));
        assertEq(wallet.isValidSignature(HASH, freshBlob), MAGIC, "re-signed blob valid");
    }


    /* ───────────────────── NESTED ABI FRAMING (never-revert) ───────────────────── */

    /// @dev The codec bounds-checks only a blob's TOP-LEVEL tail offsets. The owner ECDSA half of
    ///      a 1271 blob is reusable, so anyone holding a previously shared blob can keep it and
    ///      corrupt a NESTED tail offset (inside the PublicKey / Signature tails); Solidity's
    ///      calldata accessors revert on that overrun. `_checkErc1271Signature` contains it behind
    ///      the `erc1271Envelope` self-staticcall and must return FAIL + `MalformedErc1271Payload`
    ///      — a revert here is a DoS on the relying contract (INVARIANTS §19).
    function test_isValidSignature_neverReverts_onCorruptedNestedOffsets() public {
        SPHINCSPlusC.Signature memory sig = _signErc1271(HASH);
        bytes memory legit = _blob(erc1271Pk, sig, _ownerEcdsa(HASH));
        assertEq(wallet.isValidSignature(HASH, legit), MAGIC, "legit blob valid");

        uint256 pkOff = _word(legit, 0x00);
        uint256 sigOff = _word(legit, 0x20);

        // PublicKey tail, first head word: `statefulPublicKey` offset -> overrun.
        bytes memory pkCorrupt = _clone(legit);
        _setWord(pkCorrupt, pkOff, 1 << 64);
        _neverRevertsMalformed(pkCorrupt, "nested pk offset 2^64");

        // SPHINCS+C Signature tail, second head word: `hypertree` offset -> overrun.
        bytes memory sigCorrupt = _clone(legit);
        _setWord(sigCorrupt, sigOff + 0x20, 1 << 64);
        _neverRevertsMalformed(sigCorrupt, "nested sig offset 2^64");

        // Exact edge: the blob ends where calldata ends, so an offset whose length word starts one
        // byte past the blob is one byte past calldatasize.
        bytes memory edgeCorrupt = _clone(legit);
        _setWord(edgeCorrupt, pkOff, legit.length - pkOff - 0x20 + 1);
        _neverRevertsMalformed(edgeCorrupt, "nested pk offset 1 byte past calldata");
    }

    function _neverRevertsMalformed(bytes memory blob, string memory name) internal view {
        _neverReverts(blob, name);
        assertEq(
            uint8(wallet.debugIsValidSignature(HASH, blob)),
            uint8(IShrincsWallet.Erc1271ValidationResult.MalformedErc1271Payload),
            name
        );
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
