// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {ERC4337} from "solady-0.1.26/src/accounts/ERC4337.sol";
import {SHRINCS} from "@quip.network/hashsigs-solidity-0.2.0/contracts/SHRINCS.sol";
import {SHRINCSTestSigner} from "@quip.network/hashsigs-solidity-0.2.0/test/helpers/SHRINCSTestSigner.sol";
import {ShrincsWalletTest} from "../ShrincsWallet.t.sol";
import {ShrincsWalletCodec as Codec} from "../../../contracts/shrincs/ShrincsWalletCodec.sol";
import {IShrincsWallet} from "../../../contracts/shrincs/interfaces/IShrincsWallet.sol";
import {ShrincsWalletHarness} from "../../harness/ShrincsWalletHarness.sol";
import {ShrincsWalletMixedActionHandler} from "./support/MixedActionHandler.t.sol";

/// forge-config: default.invariant.runs = 8
/// forge-config: default.invariant.depth = 32
/// forge-config: default.invariant.fail-on-revert = true

contract ShrincsWallet_MixedActions_Invariant is ShrincsWalletTest {
    uint256 internal constant FIRST_EXECUTE = 0;
    uint256 internal constant VALIDATION = 1;
    uint256 internal constant ROTATION = 2;
    uint256 internal constant SECOND_EXECUTE = 3;
    uint256 internal constant OLD_KEY_REVOCATION = 0;
    uint256 internal constant NEW_KEY_REVOCATION = 1;
    uint256 internal constant INITIAL_BALANCE = 1 ether;
    uint256 internal constant FIRST_TRANSFER = 0.1 ether;
    uint256 internal constant SECOND_TRANSFER = 0.2 ether;

    ShrincsWalletMixedActionHandler public mixedHandler;
    bytes32 internal rotatedCommitment;
    bytes32 internal rotatedTreeId;
    uint256 internal initialNonce;
    SHRINCS.Signature internal queuedExecuteSignature;

    function _oldSink() internal view returns (address) {
        return vm.addr(0xBEEF);
    }

    function _newSink() internal view returns (address) {
        return vm.addr(0xBEF0);
    }

    function _signAction(
        SHRINCS.SigningKey memory signingKey,
        bytes32 commitment,
        uint256 nonce,
        uint256 epoch,
        bytes32 action,
        bytes32 payloadHash,
        uint32 leaf
    ) internal view returns (SHRINCS.Signature memory) {
        SHRINCS.ActionContext memory context = Codec.buildActionContext(
            wallet.exposed_shrincsDomainSeparator(),
            nonce,
            epoch,
            action,
            payloadHash
        );
        return _signStatefulActionWith(signingKey, commitment, context, leaf);
    }

    function _addExecute(
        SHRINCS.SigningKey memory signingKey,
        SHRINCS.PublicKey memory publicKey,
        bytes32 commitment,
        uint256 nonce,
        uint256 epoch,
        address target,
        uint256 value
    ) internal {
        SHRINCS.Signature memory signature = _signAction(
            signingKey,
            commitment,
            nonce,
            epoch,
            Codec.ACTION_EXECUTE,
            Codec.executePayloadHash(target, value, keccak256(""), 0),
            SIGN_BASE + 1
        );
        mixedHandler.addAction(
            abi.encodeCall(
                IShrincsWallet.execute,
                (publicKey, signature, target, value, bytes(""), uint256(0))
            ),
            false
        );
    }

    function _addValidation(uint256 nonce) internal {
        bytes32 userOpHash = keccak256("mixed-action-validation");
        SHRINCS.Signature memory signature = _signAction(
            mainKey,
            mainCommitment,
            nonce,
            0,
            Codec.ACTION_ERC4337_EXECUTE,
            Codec.erc4337PayloadHash(userOpHash),
            SIGN_BASE + 2
        );
        ERC4337.PackedUserOperation memory userOp = _makeUserOp(
            _userOpBlob(signature, userOpHash)
        );
        mixedHandler.addAction(
            abi.encodeCall(
                ShrincsWalletHarness.exposed_validateSignature,
                (userOp, userOpHash)
            ),
            true
        );
    }

    function _addRotation(
        SHRINCS.PublicKey memory nextPublicKey,
        uint256 nonce
    ) internal {
        SHRINCS.Signature memory signature = _signAction(
            mainKey,
            mainCommitment,
            nonce,
            0,
            Codec.ACTION_ROTATE_KEY,
            Codec.rotateKeyPayloadHash(rotatedCommitment),
            SIGN_BASE + 3
        );
        SHRINCS.StatefulRotationTarget memory target = SHRINCS
            .StatefulRotationTarget({
                statefulPublicKey: nextPublicKey.statefulPublicKey,
                publicKeyCommitment: nextPublicKey.publicKeyCommitment
            });
        mixedHandler.addAction(
            abi.encodeCall(
                IShrincsWallet.rotateKey,
                (_mainPk(), signature, target)
            ),
            false
        );
    }

    function _addRevocation(
        SHRINCS.SigningKey memory signingKey,
        SHRINCS.PublicKey memory publicKey,
        bytes32 commitment,
        uint256 nonce,
        uint256 epoch,
        uint256 requiredActionCount
    ) internal {
        uint32[] memory targets = new uint32[](1);
        targets[0] = SIGN_BASE + 6;
        bytes32 targetsHash = keccak256(
            abi.encodePacked(bytes32(uint256(targets[0])))
        );
        SHRINCS.Signature memory signature = _signAction(
            signingKey,
            commitment,
            nonce,
            epoch,
            Codec.ACTION_MARK_LEAVES_USED,
            Codec.markLeavesUsedPayloadHash(targetsHash),
            SIGN_BASE + 5
        );
        mixedHandler.addRevocation(
            abi.encodeCall(
                IShrincsWallet.markLeavesUsed,
                (publicKey, signature, targets)
            ),
            requiredActionCount
        );
    }

    function setUp() public override {
        super.setUp();
        initialNonce = wallet.actionNonce();
        vm.deal(WALLET, INITIAL_BALANCE);
        mixedHandler = new ShrincsWalletMixedActionHandler();
        mixedHandler.initialize(wallet, OWNER);

        (
            SHRINCS.SigningKey memory rotatedKey,
            SHRINCS.PublicKey memory generatedKey,
            bool ok
        ) = SHRINCSTestSigner.keygen("mixed-action-rotation", MAX_SIG);
        require(ok, "rotation keygen");
        SHRINCS.PublicKey memory rotatedPublicKey = SHRINCS.PublicKey({
            statefulPublicKey: generatedKey.statefulPublicKey,
            publicKeyCommitment: abi.encodePacked(
                SHRINCS.publicKeyCommitmentFromParts(
                    generatedKey.statefulPublicKey,
                    mainPk.pkSeed,
                    mainPk.hypertreeRoot
                )
            ),
            pkSeed: mainPk.pkSeed,
            hypertreeRoot: mainPk.hypertreeRoot
        });
        rotatedCommitment = _commitment32(rotatedPublicKey);
        rotatedTreeId = _treeId(rotatedPublicKey.statefulPublicKey);

        _addExecute(
            mainKey,
            _mainPk(),
            mainCommitment,
            initialNonce,
            0,
            _oldSink(),
            FIRST_TRANSFER
        );
        _addValidation(initialNonce + 1);
        queuedExecuteSignature = _signAction(
            mainKey,
            mainCommitment,
            initialNonce + 1,
            0,
            Codec.ACTION_EXECUTE,
            Codec.executePayloadHash(
                _newSink(),
                SECOND_TRANSFER,
                keccak256(""),
                0
            ),
            SIGN_BASE + 6
        );
        _addRotation(rotatedPublicKey, initialNonce + 2);
        _addExecute(
            rotatedKey,
            rotatedPublicKey,
            rotatedCommitment,
            initialNonce + 3,
            1,
            _newSink(),
            SECOND_TRANSFER
        );
        _addRevocation(
            mainKey,
            _mainPk(),
            mainCommitment,
            initialNonce + 1,
            0,
            1
        );
        _addRevocation(
            rotatedKey,
            rotatedPublicKey,
            rotatedCommitment,
            initialNonce + 3,
            1,
            3
        );

        mixedHandler.fuzzReplayAction(FIRST_EXECUTE);
        targetContract(address(mixedHandler));
        bytes4[] memory selectors = new bytes4[](2);
        selectors[0] = ShrincsWalletMixedActionHandler
            .fuzzReplayAction
            .selector;
        selectors[1] = ShrincsWalletMixedActionHandler
            .fuzzReplayRevocation
            .selector;
        targetSelector(
            FuzzSelector({addr: address(mixedHandler), selectors: selectors})
        );
    }

    function test_setUp() public view override {
        assertEq(mixedHandler.actionCount(), 4, "mixed action chain seeded");
        assertEq(mixedHandler.successfulActions(), 1, "first execute landed");
        assertEq(
            mixedHandler.unexpectedOutcomes(),
            0,
            "seeded execute accepted"
        );
        assertEq(
            wallet.actionNonce(),
            initialNonce + 1,
            "seeded execute advanced nonce"
        );
        assertEq(
            wallet.statefulLeavesUsed(),
            1,
            "seeded execute consumed one leaf"
        );
        assertEq(
            _oldSink().balance,
            FIRST_TRANSFER,
            "seeded transfer delivered"
        );
    }

    function test_mixedActions_completeSequenceAndRejectOldSignatures() public {
        mixedHandler.fuzzReplayAction(SECOND_EXECUTE);
        mixedHandler.fuzzReplayRevocation(NEW_KEY_REVOCATION);
        mixedHandler.fuzzReplayAction(ROTATION);
        mixedHandler.fuzzReplayRevocation(OLD_KEY_REVOCATION);
        mixedHandler.fuzzReplayAction(VALIDATION);
        mixedHandler.fuzzReplayAction(FIRST_EXECUTE);
        mixedHandler.fuzzReplayAction(ROTATION);
        mixedHandler.fuzzReplayRevocation(OLD_KEY_REVOCATION);
        mixedHandler.fuzzReplayRevocation(NEW_KEY_REVOCATION);
        mixedHandler.fuzzReplayAction(SECOND_EXECUTE);
        mixedHandler.fuzzReplayAction(VALIDATION);
        mixedHandler.fuzzReplayAction(ROTATION);
        mixedHandler.fuzzReplayAction(SECOND_EXECUTE);
        mixedHandler.fuzzReplayRevocation(NEW_KEY_REVOCATION);

        assertEq(
            mixedHandler.successfulActions(),
            4,
            "all action types landed in order"
        );
        assertTrue(
            mixedHandler.revocationSucceeded(OLD_KEY_REVOCATION),
            "old epoch revocation landed"
        );
        assertTrue(
            mixedHandler.revocationSucceeded(NEW_KEY_REVOCATION),
            "new epoch revocation landed"
        );
        invariant_noUnexpectedOutcome();
        invariant_stateMatchesSuccessfulActions();
        invariant_leafBitmapMatchesSuccessfulActions();
    }

    function test_mixedActions_revocationCancelsQueuedExecute() public {
        mixedHandler.fuzzReplayRevocation(OLD_KEY_REVOCATION);
        vm.expectRevert(IShrincsWallet.StaleStatefulLeaf.selector);
        vm.prank(OWNER);
        wallet.execute(
            _mainPk(),
            queuedExecuteSignature,
            _newSink(),
            SECOND_TRANSFER,
            "",
            0
        );

        mixedHandler.fuzzReplayAction(VALIDATION);
        assertEq(mixedHandler.successfulActions(), 2);
        invariant_noUnexpectedOutcome();
        invariant_stateMatchesSuccessfulActions();
        invariant_leafBitmapMatchesSuccessfulActions();
    }

    function test_mixedActions_queuedExecuteSucceedsWithoutRevocation() public {
        vm.prank(OWNER);
        wallet.execute(
            _mainPk(),
            queuedExecuteSignature,
            _newSink(),
            SECOND_TRANSFER,
            "",
            0
        );

        assertEq(wallet.actionNonce(), initialNonce + 2);
        assertEq(_newSink().balance, SECOND_TRANSFER);
        assertTrue(wallet.isStatefulLeafUsed(SIGN_BASE + 6));
    }

    function invariant_noUnexpectedOutcome() public view {
        assertEq(
            mixedHandler.unexpectedOutcomes(),
            0,
            "signed action had an unexpected result"
        );
    }

    function invariant_stateMatchesSuccessfulActions() public view {
        uint256 completed = mixedHandler.successfulActions();
        bool rotated = completed >= 3;
        uint256 spent = FIRST_TRANSFER + (completed == 4 ? SECOND_TRANSFER : 0);

        assertLe(completed, 4, "action count exceeds signed chain");
        assertEq(
            wallet.actionNonce(),
            initialNonce + completed,
            "nonce diverged"
        );
        assertEq(wallet.keyVersion(), rotated ? 1 : 0, "epoch diverged");
        assertEq(wallet.maxSignatures(), MAX_SIG, "leaf budget changed");
        assertEq(
            wallet.getShrincsPublicKeyCommitment(),
            rotated ? rotatedCommitment : mainCommitment,
            "main commitment diverged"
        );
        assertEq(
            wallet.getErc1271PublicKeyCommitment(),
            erc1271Commitment,
            "1271 key drifted"
        );
        assertEq(wallet.owner(), OWNER, "owner drifted");
        assertEq(
            factory.walletOwner(WALLET),
            OWNER,
            "factory owner registry drifted"
        );
        assertEq(
            WALLET.balance,
            INITIAL_BALANCE - spent,
            "wallet balance diverged"
        );
        assertEq(
            _oldSink().balance,
            FIRST_TRANSFER,
            "old sink balance diverged"
        );
        assertEq(
            _newSink().balance,
            completed == 4 ? SECOND_TRANSFER : 0,
            "new sink balance diverged"
        );
        assertEq(
            wallet.harness_isStatefulTreeSpent(rotatedTreeId),
            rotated,
            "new tree spent too early or missing"
        );
    }

    function invariant_leafBitmapMatchesSuccessfulActions() public view {
        uint256 completed = mixedHandler.successfulActions();
        bool rotated = completed >= 3;
        bool oldRevocation = mixedHandler.revocationSucceeded(0);
        bool newRevocation = mixedHandler.revocationSucceeded(1);
        uint256 expectedUsed = rotated
            ? (completed == 4 ? 1 : 0) + (newRevocation ? 2 : 0)
            : 1 + (completed >= 2 ? 1 : 0) + (oldRevocation ? 2 : 0);

        assertEq(
            wallet.statefulLeavesUsed(),
            expectedUsed,
            "used count diverged"
        );
        assertEq(
            wallet.remainingStatefulSignatures(),
            MAX_SIG - expectedUsed,
            "remaining budget diverged"
        );
        for (uint32 leaf = 0; leaf <= MAX_SIG + 1; leaf++) {
            bool expected = rotated
                ? (completed == 4 && leaf == SIGN_BASE + 1) ||
                    (newRevocation &&
                        (leaf == SIGN_BASE + 5 || leaf == SIGN_BASE + 6))
                : leaf == SIGN_BASE + 1 ||
                    (completed >= 2 && leaf == SIGN_BASE + 2) ||
                    (oldRevocation &&
                        (leaf == SIGN_BASE + 5 || leaf == SIGN_BASE + 6));
            assertEq(
                wallet.isStatefulLeafUsed(leaf),
                expected,
                "leaf bitmap diverged"
            );
        }
    }
}
