// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {SHRINCS} from "@quip.network/hashsigs-solidity-0.2.0/contracts/SHRINCS.sol";
import {SPHINCSPlusC} from "@quip.network/hashsigs-solidity-0.2.0/contracts/SPHINCSPlusC.sol";
import {ShrincsWalletTest} from "../ShrincsWallet.t.sol";
import {ShrincsWalletCodec as Codec} from "../../../contracts/shrincs/ShrincsWalletCodec.sol";
import {ShrincsWalletOwnershipHandler} from "./support/OwnershipHandler.t.sol";

/// forge-config: default.invariant.runs = 8
/// forge-config: default.invariant.depth = 32
/// forge-config: default.invariant.fail-on-revert = true

contract ShrincsWallet_Ownership_Invariant is ShrincsWalletTest {
    uint32 internal constant ACCEPTANCE_LEAF = 1;
    uint32 internal constant FRESH_LEAF = 2;

    ShrincsWalletOwnershipHandler public ownershipHandler;
    address internal nextOwner;
    bytes32 internal nextCommitment;
    bytes32 internal nextStatefulTree;
    bytes32 internal nextStatelessTree;
    uint256 internal nonceBeforeHandover;

    function _target() internal view returns (address) {
        return vm.addr(0xC0FFEE);
    }

    function _executeSignature(
        SHRINCS.SigningKey memory key,
        bytes32 commitment,
        uint32 leaf
    ) internal view returns (SHRINCS.Signature memory) {
        SHRINCS.ActionContext memory context = Codec.buildActionContext(
            wallet.exposed_shrincsDomainSeparator(),
            nonceBeforeHandover + 2,
            1,
            Codec.ACTION_EXECUTE,
            Codec.executePayloadHash(_target(), 0, keccak256(""), 0)
        );
        return _signStatefulActionWith(key, commitment, context, leaf);
    }

    function setUp() public override {
        super.setUp();
        uint256 nextOwnerPrivateKey;
        (nextOwner, nextOwnerPrivateKey) = makeAddrAndKey("handover recipient");
        nonceBeforeHandover = wallet.actionNonce();

        (
            SHRINCS.RotationTarget memory nextKey,
            SHRINCS.SigningKey memory nextSigningKey
        ) = _makeRotationTarget("ownership invariant incoming key");
        nextCommitment = _toBytes32(nextKey.publicKeyCommitment);
        nextStatefulTree = _treeId(nextKey.statefulPublicKey);
        nextStatelessTree = _statelessId(_bundleOf(nextKey));

        SPHINCSPlusC.Signature memory recoverySignature = _signFullRotation(
            nextKey,
            Codec.ROTATION_DOMAIN_TRANSFER_OWNERSHIP
        );
        SHRINCS.Signature memory ownerBindingSignature = _signStatefulAction(
            Codec.ACTION_TRANSFER_OWNERSHIP,
            Codec.transferOwnershipPayloadHash(nextOwner, nextCommitment),
            1
        );
        SHRINCS.Signature memory keyAcceptance = _signKeyAcceptance(
            nextSigningKey,
            nextCommitment,
            nextOwner,
            ACCEPTANCE_LEAF
        );
        bytes memory ownerAcceptance = _signOwnerAcceptance(
            nextOwnerPrivateKey,
            nextOwner,
            nextCommitment
        );

        vm.prank(OWNER);
        wallet.transferOwnership(
            _mainPk(),
            ownerBindingSignature,
            recoverySignature,
            nextKey,
            nextOwner,
            keyAcceptance,
            ownerAcceptance
        );

        ownershipHandler = new ShrincsWalletOwnershipHandler();
        ownershipHandler.initialize(
            wallet,
            _mainPk(),
            _bundleOf(nextKey),
            _executeSignature(mainKey, mainCommitment, SIGN_BASE + 2),
            _executeSignature(nextSigningKey, nextCommitment, FRESH_LEAF),
            _executeSignature(nextSigningKey, nextCommitment, ACCEPTANCE_LEAF),
            OWNER,
            nextOwner,
            _target()
        );
        targetContract(address(ownershipHandler));
        bytes4[] memory selectors = new bytes4[](4);
        selectors[0] = ShrincsWalletOwnershipHandler
            .fuzzOldOwnerCannotExecute
            .selector;
        selectors[1] = ShrincsWalletOwnershipHandler
            .fuzzOldKeyCannotExecute
            .selector;
        selectors[2] = ShrincsWalletOwnershipHandler
            .fuzzAcceptanceLeafCannotExecute
            .selector;
        selectors[3] = ShrincsWalletOwnershipHandler
            .fuzzNewOwnerExecutes
            .selector;
        targetSelector(
            FuzzSelector({
                addr: address(ownershipHandler),
                selectors: selectors
            })
        );
    }

    function test_setUp() public view override {
        assertEq(ownershipHandler.freshActionExecuted(), false);
        invariant_ownerAndFactoryRegistryAgree();
        invariant_nonceAndEpochTrackHandover();
        invariant_newEpochBitmapMatchesAcceptanceAndActions();
        invariant_commitmentsAndBudgetMatchIncomingKey();
        invariant_oldAndNewTreesAreSpent();
    }

    function test_newOwnerActsAndOldOwnerCannotReuseAuthority() public {
        ownershipHandler.fuzzOldOwnerCannotExecute();
        ownershipHandler.fuzzOldKeyCannotExecute();
        ownershipHandler.fuzzAcceptanceLeafCannotExecute();
        ownershipHandler.fuzzNewOwnerExecutes();
        ownershipHandler.fuzzNewOwnerExecutes();
        ownershipHandler.fuzzOldOwnerCannotExecute();
        assertEq(ownershipHandler.oldOwnerRejections(), 2);
        assertEq(ownershipHandler.oldKeyRejections(), 1);
        assertEq(ownershipHandler.acceptanceReplayRejections(), 1);
        assertEq(ownershipHandler.freshActionReplays(), 1);
        invariant_nonceAndEpochTrackHandover();
        invariant_newEpochBitmapMatchesAcceptanceAndActions();
    }

    function invariant_ownerAndFactoryRegistryAgree() public view {
        assertEq(wallet.owner(), nextOwner);
        assertEq(factory.walletOwner(WALLET), nextOwner);
    }

    function invariant_nonceAndEpochTrackHandover() public view {
        assertEq(wallet.keyVersion(), 1);
        assertEq(
            wallet.actionNonce(),
            nonceBeforeHandover +
                2 +
                (ownershipHandler.freshActionExecuted() ? 1 : 0)
        );
    }

    function invariant_newEpochBitmapMatchesAcceptanceAndActions() public view {
        bool freshActionExecuted = ownershipHandler.freshActionExecuted();
        uint32 usedLeaves = freshActionExecuted ? 2 : 1;
        assertEq(wallet.statefulLeavesUsed(), usedLeaves);
        assertEq(wallet.remainingStatefulSignatures(), MAX_SIG - usedLeaves);
        for (uint32 leaf = 0; leaf <= MAX_SIG + 1; leaf++) {
            bool expectedUsed = leaf == ACCEPTANCE_LEAF ||
                (freshActionExecuted && leaf == FRESH_LEAF);
            assertEq(wallet.isStatefulLeafUsed(leaf), expectedUsed);
        }
    }

    function invariant_commitmentsAndBudgetMatchIncomingKey() public view {
        assertEq(wallet.getShrincsPublicKeyCommitment(), nextCommitment);
        assertEq(wallet.getErc1271PublicKeyCommitment(), erc1271Commitment);
        assertEq(wallet.maxSignatures(), MAX_SIG);
    }

    function invariant_oldAndNewTreesAreSpent() public view {
        assertTrue(
            wallet.harness_isStatefulTreeSpent(
                _treeId(mainPk.statefulPublicKey)
            )
        );
        assertTrue(wallet.harness_isStatelessTreeSpent(_statelessId(mainPk)));
        assertTrue(wallet.harness_isStatefulTreeSpent(nextStatefulTree));
        assertTrue(wallet.harness_isStatelessTreeSpent(nextStatelessTree));
    }
}
