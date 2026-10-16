// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {SHRINCS} from "@quip.network/hashsigs-solidity-0.2.0/contracts/SHRINCS.sol";
import {SPHINCSPlusC} from "@quip.network/hashsigs-solidity-0.2.0/contracts/SPHINCSPlusC.sol";
import {SHRINCSVerifier} from "@quip.network/hashsigs-solidity-0.2.0/contracts/SHRINCSVerifier.sol";
import {ShrincsWalletCodec as Codec} from "../../../contracts/shrincs/ShrincsWalletCodec.sol";
import {ShrincsWalletTest} from "../ShrincsWallet.t.sol";

/// @dev Behavior tests for the internal `_tryVerifyStateless` (via the harness) — the stateless
///      twin of `_tryVerifyStateful`, targeting the verifier's `verifyStateless`. Same policy:
///      every rejection and every revert-as-rejection maps to false; only a codeless verifier
///      stays loud.
contract ShrincsWallet__tryVerifyStateless is ShrincsWalletTest {
    bytes32 internal constant HASH = keccak256("try-verify-stateless-hash");

    /// @dev A valid (messageHash, envelope) pair over the wallet's canonical ERC-1271 context,
    ///      signed by the dedicated 1271 stateless key.
    function _validPair() internal returns (bytes32 messageHash, bytes memory envelope) {
        SHRINCS.ActionContext memory ctx = _actionContext(Codec.ACTION_ERC1271, HASH);
        messageHash = SHRINCS.statelessActionMessageHash(erc1271Commitment, ctx);
        SPHINCSPlusC.Signature memory sig = _signErc1271(HASH);
        envelope = abi.encode(erc1271Pk, sig);
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

    /// @dev The revert-as-rejection policy pin: an all-empty stateless signature panics inside
    ///      the verifier's envelope slicing (`hypertree.length - 1` underflow) — the try/catch
    ///      must report it as plain false.
    function test_tryVerifyStateless_falseWhen_garbageSignatureInternals() public view {
        SPHINCSPlusC.Signature memory garbage;
        assertFalse(
            wallet.exposed_tryVerifyStateless(
                erc1271Commitment, keccak256("any message"), abi.encode(erc1271Pk, garbage)
            )
        );
    }

    /// @dev A missing verifier must stay LOUD (decoding errors are deliberately not swallowed).
    function test_tryVerifyStateless_revertsWhen_verifierCodeRemoved() public {
        (bytes32 messageHash, bytes memory envelope) = _validPair();
        vm.etch(address(shrincsVerifier), "");
        vm.expectRevert();
        wallet.exposed_tryVerifyStateless(erc1271Commitment, messageHash, envelope);
    }
}
