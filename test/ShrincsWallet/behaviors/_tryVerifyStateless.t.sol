// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {StatelessLayout} from "@quip.network/hashsigs-solidity-0.4.0/contracts/StatelessLayout.sol";
import {SHRINCS} from "@quip.network/hashsigs-solidity-0.4.0/contracts/SHRINCS.sol";
import {SHRINCSVerifier} from "@quip.network/hashsigs-solidity-0.4.0/contracts/SHRINCSVerifier.sol";
import {ShrincsWalletCodec as Codec} from "../../../contracts/shrincs/ShrincsWalletCodec.sol";
import {ShrincsWalletTest} from "../ShrincsWallet.t.sol";

/// @dev Behavior tests for the internal `_tryVerifyStateless` (via the harness) — the stateless
///      twin of `_tryVerifyStateful`, targeting the verifier's `verifyStateless`. Same policy:
///      every rejection and every revert-as-rejection maps to false; only a codeless verifier
///      stays loud.
contract ShrincsWallet__tryVerifyStateless is ShrincsWalletTest {
    bytes32 internal constant HASH = keccak256("try-verify-stateless-hash");

    /// @dev A valid (messageHash, `PK ‖ PQ` payload) pair over the wallet's canonical ERC-1271
    ///      context, signed by the dedicated 1271 stateless key.
    function _validPair() internal returns (bytes32 messageHash, bytes memory envelope) {
        SHRINCS.ActionContext memory ctx = _actionContext(Codec.ACTION_ERC1271, HASH);
        messageHash = SHRINCS.statelessActionMessageHash(erc1271Commitment, ctx);
        bytes memory sig = _signErc1271(HASH);
        envelope = _statelessPayload(erc1271Pk, sig);
    }

    function test_tryVerifyStateless_trueForValidSignature() public {
        (bytes32 messageHash, bytes memory envelope) = _validPair();
        vm.expectCall(
            address(shrincsVerifier), abi.encodeWithSelector(SHRINCSVerifier.verifyStateless.selector)
        );
        assertTrue(wallet.exposed_tryVerifyStateless(erc1271Commitment, messageHash, envelope));
    }

    function test_tryVerifyStateless_falseWhen_wrongMessageHash() public {
        (, bytes memory envelope) = _validPair();
        assertFalse(
            wallet.exposed_tryVerifyStateless(erc1271Commitment, keccak256("some other message"), envelope)
        );
    }

    function test_tryVerifyStateless_falseWhen_commitmentMismatch() public {
        (bytes32 messageHash, bytes memory envelope) = _validPair();
        // The verifier's bundle-vs-commitment check rejects a foreign expected commitment.
        assertFalse(
            wallet.exposed_tryVerifyStateless(mainCommitment, messageHash, envelope)
        );
    }

    /// @dev An empty PQ section gives a wrong-length payload. Since 0.4.0 the verifier returns
    ///      the failure selector for it instead of reverting; either way the wallet reports false.
    function test_tryVerifyStateless_falseWhen_garbageSignatureInternals() public view {
        bytes memory garbage;
        assertFalse(
            wallet.exposed_tryVerifyStateless(
                erc1271Commitment, keccak256("any message"), _statelessPayload(erc1271Pk, garbage)
            )
        );
    }

    function test_tryVerifyStateless_falseWhen_wrongPayloadLength() public {
        (bytes32 messageHash, bytes memory payload) = _validPair();
        assertEq(payload.length, StatelessLayout.PAYLOAD_LEN, "fixture: valid payload has the exact length");
        assertFalse(
            wallet.exposed_tryVerifyStateless(erc1271Commitment, messageHash, abi.encodePacked(payload, bytes1(0))),
            "one byte long"
        );
        assembly {
            mstore(payload, sub(mload(payload), 1))
        }
        assertFalse(wallet.exposed_tryVerifyStateless(erc1271Commitment, messageHash, payload), "one byte short");
    }

    function test_tryVerifyStateless_falseWhen_garbagePayload() public view {
        assertFalse(
            wallet.exposed_tryVerifyStateless(
                erc1271Commitment, keccak256("m"), new bytes(StatelessLayout.PAYLOAD_LEN)
            )
        );
    }

    /// @dev A single flipped bit anywhere in the PQ section invalidates the signature.
    function test_tryVerifyStateless_falseWhen_pqBitFlipped() public {
        (bytes32 messageHash, bytes memory payload) = _validPair();
        payload[payload.length - 1] ^= 0x01;
        assertFalse(wallet.exposed_tryVerifyStateless(erc1271Commitment, messageHash, payload));
    }

    /// @dev Revert-as-rejection: a verifier that reverts is reported as plain false.
    function test_tryVerifyStateless_falseWhen_verifierReverts() public {
        vm.mockCallRevert(
            address(shrincsVerifier), abi.encodeWithSelector(SHRINCSVerifier.verifyStateless.selector), "boom"
        );
        assertFalse(
            wallet.exposed_tryVerifyStateless(
                erc1271Commitment, keccak256("m"), new bytes(StatelessLayout.PAYLOAD_LEN)
            )
        );
    }

    /// @dev Only the exact ERC-7913 success selector counts.
    function test_tryVerifyStateless_falseWhen_verifierReturnsOtherSelector() public {
        vm.mockCall(
            address(shrincsVerifier),
            abi.encodeWithSelector(SHRINCSVerifier.verifyStateless.selector),
            abi.encode(bytes4(0x12345678))
        );
        assertFalse(
            wallet.exposed_tryVerifyStateless(
                erc1271Commitment, keccak256("m"), new bytes(StatelessLayout.PAYLOAD_LEN)
            )
        );
    }

    /// @dev The verifier pins its SPHINCSPlusC sibling by address. With the sibling undeployed the
    ///      verifier reverts, which the wallet reports as a rejection, not a revert.
    function test_tryVerifyStateless_falseWhen_siblingCodeRemoved() public {
        (bytes32 messageHash, bytes memory payload) = _validPair();
        vm.etch(SPHINCS_SIBLING, "");
        assertFalse(wallet.exposed_tryVerifyStateless(erc1271Commitment, messageHash, payload));
    }

    /// @dev A missing verifier must stay LOUD (decoding errors are deliberately not swallowed).
    function test_tryVerifyStateless_revertsWhen_verifierCodeRemoved() public {
        (bytes32 messageHash, bytes memory envelope) = _validPair();
        vm.etch(address(shrincsVerifier), "");
        vm.expectRevert();
        wallet.exposed_tryVerifyStateless(erc1271Commitment, messageHash, envelope);
    }
}
