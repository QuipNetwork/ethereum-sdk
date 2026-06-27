// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {ShrincsTypes} from "@quip.network/hashsigs-solidity-0.1.0/contracts/ShrincsTypes.sol";
import {IShrincsWallet} from "../../../contracts/shrincs/interfaces/IShrincsWallet.sol";
import {ShrincsWalletTest} from "../ShrincsWallet.t.sol";

/// @dev Behavior tests for ERC-1271 `isValidSignature` / `debugIsValidSignature` /
///      `_checkErc1271Signature`. The length, ECDSA, and stateless-failure branches are testable
///      now (the ECDSA half is owner-controlled), and the full `Ok` path is exercised by the
///      regenerated stateless ERC-1271 vector.
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

    function _ownerSig(bytes32 hash) internal view returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(OWNER_PK, wallet.quipSignedHashEcdsaTarget(hash));
        return abi.encodePacked(r, s, v);
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
        bytes memory blob =
            _blob(_parsePublicKey(".erc1271Key"), _parseStatelessSignature(""), abi.encodePacked(r, s, v));

        assertEq(wallet.isValidSignature(HASH, blob), FAIL);
        assertEq(
            uint8(wallet.debugIsValidSignature(HASH, blob)),
            uint8(IShrincsWallet.Erc1271ValidationResult.InvalidEcdsaSignature)
        );
    }

    function test_isValidSignature_revertsWhen_invalidShrincs() public {
        // Owner ECDSA is valid, but the (empty) stateless signature fails SHRINCS verification.
        bytes memory blob = _blob(_parsePublicKey(".erc1271Key"), _parseStatelessSignature(""), _ownerSig(HASH));

        assertEq(wallet.isValidSignature(HASH, blob), FAIL);
        assertEq(
            uint8(wallet.debugIsValidSignature(HASH, blob)),
            uint8(IShrincsWallet.Erc1271ValidationResult.InvalidShrincsSignature)
        );
    }

    function test_isValidSignature_ok() public view {
        bytes32 hash = _bytes32(".cases.erc1271.hash");
        ShrincsTypes.StatelessSignature memory sig = _parseStatelessSignature(".cases.erc1271.signature");
        bytes memory blob = _blob(_parsePublicKey(".erc1271Key"), sig, _ownerSig(hash));
        assertEq(wallet.isValidSignature(hash, blob), MAGIC);
        assertEq(uint8(wallet.debugIsValidSignature(hash, blob)), uint8(IShrincsWallet.Erc1271ValidationResult.Ok));
    }
}
