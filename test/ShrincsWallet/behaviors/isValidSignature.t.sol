// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {ShrincsTypes} from "@quip.network/hashsigs-solidity-0.2.0/contracts/ShrincsTypes.sol";
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
    function _blob(ShrincsTypes.PublicKey memory pk, ShrincsTypes.StatelessSignature memory sig, bytes memory ecdsaSig)
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
        ShrincsTypes.StatelessSignature memory emptySig;
        bytes memory blob = _blob(erc1271Pk, emptySig, abi.encodePacked(r, s, v));

        assertEq(wallet.isValidSignature(HASH, blob), FAIL);
        assertEq(
            uint8(wallet.debugIsValidSignature(HASH, blob)),
            uint8(IShrincsWallet.Erc1271ValidationResult.InvalidEcdsaSignature)
        );
    }

    function test_isValidSignature_revertsWhen_invalidShrincs() public {
        // Owner ECDSA is valid, but the (empty) stateless signature fails SHRINCS verification.
        ShrincsTypes.StatelessSignature memory emptySig;
        bytes memory blob = _blob(erc1271Pk, emptySig, _ownerEcdsa(HASH));

        assertEq(wallet.isValidSignature(HASH, blob), FAIL);
        assertEq(
            uint8(wallet.debugIsValidSignature(HASH, blob)),
            uint8(IShrincsWallet.Erc1271ValidationResult.InvalidShrincsSignature)
        );
    }

    function test_isValidSignature_ok() public {
        ShrincsTypes.StatelessSignature memory sig = _signErc1271(HASH);
        bytes memory blob = _blob(erc1271Pk, sig, _ownerEcdsa(HASH));
        assertEq(wallet.isValidSignature(HASH, blob), MAGIC);
        assertEq(uint8(wallet.debugIsValidSignature(HASH, blob)), uint8(IShrincsWallet.Erc1271ValidationResult.Ok));
    }

    /// @dev Intended supersession: the 1271 context binds the LIVE action nonce, so a blob dies
    ///      the moment any wallet signature is consumed — and a fresh re-sign is valid again.
    function test_isValidSignature_staleNonceRejected_freshResignOk() public {
        ShrincsTypes.StatelessSignature memory sig = _signErc1271(HASH);
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
        ShrincsTypes.StatelessSignature memory fresh = _signErc1271(HASH);
        bytes memory freshBlob = _blob(erc1271Pk, fresh, _ownerEcdsa(HASH));
        assertEq(wallet.isValidSignature(HASH, freshBlob), MAGIC, "re-signed blob valid");
    }
}
