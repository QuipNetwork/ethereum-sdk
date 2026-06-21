// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {Ownable} from "solady-0.1.26/src/auth/Ownable.sol";
import {ShrincsTypes} from "@quip.network/hashsigs-solidity-0.1.0/contracts/ShrincsTypes.sol";
import {IShrincsWallet} from "../../../contracts/shrincs/interfaces/IShrincsWallet.sol";
import {ShrincsWalletTest} from "../ShrincsWallet.t.sol";

/// @dev Behavior tests for stateful `rotateKey`. The input-validation reverts (target length /
///      zero maxSignatures), leaf guards, and `InvalidSignature`, plus the regenerated-vector
///      success path (new stateful subkey, reused stateless root, `keyVersion++`, nonce unchanged)
///      are all exercised.
contract ShrincsWallet_rotateKey is ShrincsWalletTest {
    function _pk() internal view returns (ShrincsTypes.PublicKey memory) {
        return _parsePublicKey(".mainKey");
    }

    /// @dev A structurally-valid 68-byte stateful rotation target (from the vectors).
    function _validTarget() internal view returns (ShrincsTypes.StatefulRotationTarget memory) {
        return _parseStatefulRotationTarget(".cases.rotateKey.nextStatefulKey");
    }

    function test_rotateKey_revertsWhen_notOwner() public {
        vm.prank(makeAddr("stranger"));
        vm.expectRevert(Ownable.Unauthorized.selector);
        wallet.rotateKey(_pk(), _statefulSigWithLeaf(1), _validTarget());
    }

    function test_rotateKey_revertsWhen_badStatefulKeyLength() public {
        ShrincsTypes.StatefulRotationTarget memory t;
        t.parameterSetId = ShrincsTypes.ParameterSetId(0);
        t.statefulPublicKey = hex"00112233"; // not 68 bytes
        t.publicKeyCommitment = abi.encodePacked(bytes32(0));

        vm.prank(OWNER);
        vm.expectRevert(IShrincsWallet.CommitmentMismatch.selector);
        wallet.rotateKey(_pk(), _statefulSigWithLeaf(1), t);
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
        wallet.rotateKey(_pk(), _statefulSigWithLeaf(1), t);
    }

    function test_rotateKey_revertsWhen_leafZero() public {
        vm.prank(OWNER);
        vm.expectRevert(IShrincsWallet.StatefulBudgetExhausted.selector);
        wallet.rotateKey(_pk(), _statefulSigWithLeaf(0), _validTarget());
    }

    function test_rotateKey_revertsWhen_leafAlreadyUsed() public {
        wallet.harness_markLeafUsed(1);
        vm.prank(OWNER);
        vm.expectRevert(IShrincsWallet.StaleStatefulLeaf.selector);
        wallet.rotateKey(_pk(), _statefulSigWithLeaf(1), _validTarget());
    }

    function test_rotateKey_revertsWhen_invalidSignature() public {
        vm.prank(OWNER);
        vm.expectRevert(IShrincsWallet.InvalidSignature.selector);
        wallet.rotateKey(_pk(), _wrongContextStatefulSig(), _validTarget());
    }

    function test_rotateKey_succeeds() public {
        ShrincsTypes.StatefulSignature memory sig = _parseStatefulSignature(".cases.rotateKey.signature");
        bytes32 nextCommitment = _bytes32(".cases.rotateKey.nextCommitment");
        uint256 nonceBefore = wallet.actionNonce();
        vm.prank(OWNER);
        wallet.rotateKey(_pk(), sig, _validTarget());
        assertEq(wallet.getShrincsPublicKeyCommitment(), nextCommitment, "new stateful subkey installed");
        assertEq(wallet.keyVersion(), 1, "epoch bumped");
        assertEq(wallet.actionNonce(), nonceBefore, "rotateKey leaves the action nonce unchanged");
        assertEq(wallet.statefulLeavesUsed(), 0, "fresh epoch counter");
    }
}
