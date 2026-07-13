// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {Ownable} from "solady-0.1.26/src/auth/Ownable.sol";
import {ShrincsTypes} from "@quip.network/hashsigs-solidity-0.1.0/contracts/ShrincsTypes.sol";
import {ShrincsWalletCodec as Codec} from "../../../contracts/shrincs/ShrincsWalletCodec.sol";
import {IShrincsWallet} from "../../../contracts/shrincs/interfaces/IShrincsWallet.sol";
import {ShrincsWalletTest} from "../ShrincsWallet.t.sol";

/// @dev Behavior tests for stateful `rotateKey`. The input-validation reverts (target length /
///      zero maxSignatures), leaf guards, `InvalidSignature`, and the live-signed success path
///      (new stateful subkey, reused stateless root, `keyVersion++`, nonce unchanged) are all
///      exercised.
contract ShrincsWallet_rotateKey is ShrincsWalletTest {
    /// @dev A structurally-valid 68-byte stateful rotation target (freshly generated subkey).
    function _validTarget() internal view returns (ShrincsTypes.StatefulRotationTarget memory t) {
        (t,) = _makeStatefulRotationTarget("rotate-key-next-stateful");
    }

    function test_rotateKey_revertsWhen_notOwner() public {
        vm.prank(makeAddr("stranger"));
        vm.expectRevert(Ownable.Unauthorized.selector);
        wallet.rotateKey(_mainPk(), _statefulSigWithLeaf(1), _validTarget());
    }

    function test_rotateKey_revertsWhen_badStatefulKeyLength() public {
        ShrincsTypes.StatefulRotationTarget memory t;
        t.statefulPublicKey = hex"00112233"; // not 68 bytes
        t.publicKeyCommitment = abi.encodePacked(bytes32(0));

        vm.prank(OWNER);
        vm.expectRevert(IShrincsWallet.CommitmentMismatch.selector);
        wallet.rotateKey(_mainPk(), _statefulSigWithLeaf(1), t);
    }

    function test_rotateKey_revertsWhen_zeroMaxSignatures() public {
        ShrincsTypes.StatefulRotationTarget memory t = _validTarget();
        bytes memory spk = t.statefulPublicKey;
        spk[64] = 0;
        spk[65] = 0;
        spk[66] = 0;
        spk[67] = 0; // zero the trailing maxSignatures
        t.statefulPublicKey = spk;

        vm.prank(OWNER);
        vm.expectRevert(IShrincsWallet.ZeroMaxSignatures.selector);
        wallet.rotateKey(_mainPk(), _statefulSigWithLeaf(1), t);
    }

    function test_rotateKey_revertsWhen_leafZero() public {
        vm.prank(OWNER);
        vm.expectRevert(IShrincsWallet.StatefulBudgetExhausted.selector);
        wallet.rotateKey(_mainPk(), _statefulSigWithLeaf(0), _validTarget());
    }

    function test_rotateKey_revertsWhen_leafAlreadyUsed() public {
        wallet.harness_markLeafUsed(1);
        vm.prank(OWNER);
        vm.expectRevert(IShrincsWallet.StaleStatefulLeaf.selector);
        wallet.rotateKey(_mainPk(), _statefulSigWithLeaf(1), _validTarget());
    }

    function test_rotateKey_revertsWhen_invalidSignature() public {
        ShrincsTypes.StatefulSignature memory sig = _wrongContextStatefulSig();
        ShrincsTypes.StatefulRotationTarget memory target = _validTarget();
        vm.prank(OWNER);
        vm.expectRevert(IShrincsWallet.InvalidSignature.selector);
        wallet.rotateKey(_mainPk(), sig, target);
    }

    function test_rotateKey_succeeds() public {
        (ShrincsTypes.StatefulRotationTarget memory t, bytes32 nextCommitment) =
            _makeStatefulRotationTarget("rotate-key-next-stateful");
        ShrincsTypes.StatefulSignature memory sig =
            _signStatefulAction(Codec.ACTION_ROTATE_KEY, Codec.rotateKeyPayloadHash(nextCommitment), 1);
        uint256 nonceBefore = wallet.actionNonce();
        vm.prank(OWNER);
        wallet.rotateKey(_mainPk(), sig, t);
        assertEq(wallet.getShrincsPublicKeyCommitment(), nextCommitment, "new stateful subkey installed");
        assertEq(wallet.keyVersion(), 1, "epoch bumped");
        assertEq(wallet.actionNonce(), nonceBefore + 1, "rotateKey advances the action nonce (+1 via the shared core)");
        assertEq(wallet.statefulLeavesUsed(), 0, "fresh epoch counter");
    }
}
