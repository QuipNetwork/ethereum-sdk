// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {ShrincsTypes} from "@quip.network/hashsigs-solidity-0.2.0/contracts/ShrincsTypes.sol";
import {IShrincsWallet} from "../../../contracts/shrincs/interfaces/IShrincsWallet.sol";
import {ShrincsWalletTest} from "../ShrincsWallet.t.sol";

/// @dev Behavior tests for the internal `_checkErc1271Signature` (via `exposed_checkErc1271Signature`),
///      which returns the discriminated `Erc1271ValidationResult`. Order of checks: length →
///      ECDSA-recover-vs-owner → stateless SHRINCS against the dedicated ERC-1271 verifier key. The
///      ECDSA half is an AND-gate failsafe, so a valid stateless half alone is never enough.
contract ShrincsWallet__checkErc1271Signature is ShrincsWalletTest {
    bytes32 internal constant HASH = keccak256("erc1271-internal-message");

    function _blob(ShrincsTypes.PublicKey memory pk, ShrincsTypes.StatelessSignature memory sig, bytes memory ecdsaSig)
        internal
        pure
        returns (bytes memory)
    {
        return abi.encode(pk, sig, ecdsaSig);
    }

    function _result(bytes32 hash, bytes memory blob) internal view returns (IShrincsWallet.Erc1271ValidationResult) {
        return wallet.exposed_checkErc1271Signature(hash, blob);
    }

    function test_checkErc1271_ok() public {
        ShrincsTypes.StatelessSignature memory sig = _signErc1271(HASH);
        bytes memory blob = _blob(erc1271Pk, sig, _ownerEcdsa(HASH));
        assertEq(uint8(_result(HASH, blob)), uint8(IShrincsWallet.Erc1271ValidationResult.Ok));
    }

    function test_checkErc1271_badSignatureLength() public view {
        // < 0x60 bytes cannot carry the three ABI head words.
        assertEq(uint8(_result(HASH, hex"1234")), uint8(IShrincsWallet.Erc1271ValidationResult.BadSignatureLength));
    }

    function test_checkErc1271_invalidEcdsa_wrongSigner() public {
        // Stateless half structurally present but ECDSA recovers a non-owner ⇒ fails at the gate.
        (, uint256 wrongPk) = makeAddrAndKey("wrongSigner");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(wrongPk, wallet.quipSignedHashEcdsaTarget(HASH));
        ShrincsTypes.StatelessSignature memory emptySig;
        bytes memory blob = _blob(erc1271Pk, emptySig, abi.encodePacked(r, s, v));
        assertEq(uint8(_result(HASH, blob)), uint8(IShrincsWallet.Erc1271ValidationResult.InvalidEcdsaSignature));
    }

    function test_checkErc1271_invalidEcdsa_unrecoverable() public view {
        // A 65-byte but garbage ECDSA signature recovers address(0) ⇒ rejected before SHRINCS.
        bytes memory garbage = new bytes(65);
        ShrincsTypes.StatelessSignature memory emptySig;
        bytes memory blob = _blob(erc1271Pk, emptySig, garbage);
        assertEq(uint8(_result(HASH, blob)), uint8(IShrincsWallet.Erc1271ValidationResult.InvalidEcdsaSignature));
    }

    function test_checkErc1271_invalidShrincs() public {
        // Owner ECDSA valid, but an empty stateless signature fails SHRINCS verification.
        ShrincsTypes.StatelessSignature memory emptySig;
        bytes memory blob = _blob(erc1271Pk, emptySig, _ownerEcdsa(HASH));
        assertEq(uint8(_result(HASH, blob)), uint8(IShrincsWallet.Erc1271ValidationResult.InvalidShrincsSignature));
    }

    function test_checkErc1271_wrongHashFailsShrincs() public {
        // The signature is bound to `HASH`; presenting it under a different message (with a
        // matching owner ECDSA over that other message) fails SHRINCS.
        bytes32 otherHash = keccak256("a-different-message");
        ShrincsTypes.StatelessSignature memory sig = _signErc1271(HASH);
        bytes memory blob = _blob(erc1271Pk, sig, _ownerEcdsa(otherHash));
        assertEq(uint8(_result(otherHash, blob)), uint8(IShrincsWallet.Erc1271ValidationResult.InvalidShrincsSignature));
    }
}
