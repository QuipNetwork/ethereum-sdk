// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {SHRINCS} from "@quip.network/hashsigs-solidity-0.2.0/contracts/SHRINCS.sol";
import {SPHINCSPlusC} from "@quip.network/hashsigs-solidity-0.2.0/contracts/SPHINCSPlusC.sol";
import {ShrincsWalletTest} from "../ShrincsWallet.t.sol";
import {ShrincsWalletCodec as Codec} from "../../../contracts/shrincs/ShrincsWalletCodec.sol";
import {IShrincsWallet} from "../../../contracts/shrincs/interfaces/IShrincsWallet.sol";
import {ShrincsWalletRecoveryHandler} from "./support/RecoveryHandler.t.sol";

/// forge-config: default.invariant.runs = 8
/// forge-config: default.invariant.depth = 24
/// forge-config: default.invariant.fail-on-revert = true

contract ShrincsWallet_Recovery_Invariant is ShrincsWalletTest {
    uint256 internal constant WALLET_FUNDS = 1 ether;
    uint256 internal constant NEW_TRANSFER = 0.1 ether;
    uint256 internal constant OLD_TRANSFER = 0.2 ether;

    ShrincsWalletRecoveryHandler public recoveryHandler;
    uint256 internal initialNonce;
    bytes32 internal recoveredCommitment;
    bytes32 internal recoveredStatefulTree;
    bytes32 internal recoveredStatelessTree;

    function _oldSink() internal view returns (address) {
        return vm.addr(0xD001);
    }

    function _newSink() internal view returns (address) {
        return vm.addr(0xD002);
    }

    function _signedExecute(
        SHRINCS.SigningKey memory key,
        bytes32 commitment,
        uint256 nonce,
        uint256 epoch,
        address target,
        uint256 value,
        uint32 leaf
    ) internal view returns (SHRINCS.Signature memory) {
        SHRINCS.ActionContext memory context = Codec.buildActionContext(
            wallet.exposed_shrincsDomainSeparator(),
            nonce,
            epoch,
            Codec.ACTION_EXECUTE,
            Codec.executePayloadHash(target, value, keccak256(""), 0)
        );
        return _signStatefulActionWith(key, commitment, context, leaf);
    }

    function _executeCall(
        SHRINCS.PublicKey memory publicKey,
        SHRINCS.Signature memory signature,
        address target,
        uint256 value
    ) internal pure returns (bytes memory) {
        return
            abi.encodeCall(
                IShrincsWallet.execute,
                (publicKey, signature, target, value, bytes(""), uint256(0))
            );
    }

    function setUp() public override {
        super.setUp();
        initialNonce = wallet.actionNonce();
        vm.deal(WALLET, WALLET_FUNDS);

        SHRINCS.Signature memory seedSignature = _signedExecute(
            mainKey,
            mainCommitment,
            initialNonce,
            0,
            address(0),
            0,
            SIGN_BASE + 1
        );
        vm.prank(OWNER);
        wallet.execute(_mainPk(), seedSignature, address(0), 0, "", 0);

        SHRINCS.Signature memory oldPendingSignature = _signedExecute(
            mainKey,
            mainCommitment,
            initialNonce + 1,
            0,
            _oldSink(),
            OLD_TRANSFER,
            SIGN_BASE + 2
        );
        (
            SHRINCS.RotationTarget memory nextKey,
            SHRINCS.SigningKey memory nextSigningKey
        ) = _makeRotationTarget("invariant-recovery-next-key");
        SPHINCSPlusC.Signature memory recoverySignature = _signFullRotation(
            nextKey,
            Codec.ROTATION_DOMAIN_RECOVER_WALLET
        );
        SHRINCS.PublicKey memory nextPublicKey = _bundleOf(nextKey);
        recoveredCommitment = _commitment32(nextPublicKey);
        recoveredStatefulTree = _treeId(nextKey.statefulPublicKey);
        recoveredStatelessTree = _statelessId(nextPublicKey);

        SHRINCS.Signature memory newSignature = _signedExecute(
            nextSigningKey,
            recoveredCommitment,
            initialNonce + 2,
            1,
            _newSink(),
            NEW_TRANSFER,
            SIGN_BASE + 3
        );
        SHRINCS.Signature memory oldKeyCurrentContextSignature = _signedExecute(
            mainKey,
            mainCommitment,
            initialNonce + 2,
            1,
            _oldSink(),
            OLD_TRANSFER,
            SIGN_BASE + 4
        );

        recoveryHandler = new ShrincsWalletRecoveryHandler();
        recoveryHandler.initialize(
            wallet,
            OWNER,
            abi.encodeCall(
                IShrincsWallet.recoverWallet,
                (_mainPk(), recoverySignature, nextKey)
            ),
            _executeCall(
                _mainPk(),
                oldPendingSignature,
                _oldSink(),
                OLD_TRANSFER
            ),
            _executeCall(
                _mainPk(),
                oldKeyCurrentContextSignature,
                _oldSink(),
                OLD_TRANSFER
            ),
            _executeCall(nextPublicKey, newSignature, _newSink(), NEW_TRANSFER)
        );

        targetContract(address(recoveryHandler));
        bytes4[] memory selectors = new bytes4[](3);
        selectors[0] = ShrincsWalletRecoveryHandler.fuzzRecover.selector;
        selectors[1] = ShrincsWalletRecoveryHandler.fuzzOldExecute.selector;
        selectors[2] = ShrincsWalletRecoveryHandler.fuzzNewExecute.selector;
        targetSelector(
            FuzzSelector({addr: address(recoveryHandler), selectors: selectors})
        );
    }

    function test_setUp() public view override {
        assertEq(wallet.owner(), OWNER);
        assertEq(wallet.actionNonce(), initialNonce + 1);
        assertEq(wallet.keyVersion(), 0);
        assertEq(wallet.statefulLeavesUsed(), 1);
        assertTrue(wallet.isStatefulLeafUsed(SIGN_BASE + 1));
        assertEq(wallet.getShrincsPublicKeyCommitment(), mainCommitment);
        assertFalse(recoveryHandler.recovered());
        assertFalse(recoveryHandler.newExecuteLanded());
    }

    function test_oldPendingSignatureWorksBeforeRecovery() public {
        SHRINCS.Signature memory signature = _signedExecute(
            mainKey,
            mainCommitment,
            initialNonce + 1,
            0,
            _oldSink(),
            OLD_TRANSFER,
            SIGN_BASE + 2
        );
        vm.prank(OWNER);
        wallet.execute(_mainPk(), signature, _oldSink(), OLD_TRANSFER, "", 0);
        assertEq(wallet.actionNonce(), initialNonce + 2);
        assertEq(wallet.statefulLeavesUsed(), 2);
        assertEq(_oldSink().balance, OLD_TRANSFER);
        assertEq(WALLET.balance, WALLET_FUNDS - OLD_TRANSFER);
    }

    function test_recoveryThenNewKeyExecuteRejectsOldKey() public {
        recoveryHandler.fuzzNewExecute();
        recoveryHandler.fuzzRecover();
        recoveryHandler.fuzzOldExecute();
        recoveryHandler.fuzzNewExecute();
        recoveryHandler.fuzzRecover();
        recoveryHandler.fuzzOldExecute();
        recoveryHandler.fuzzNewExecute();

        assertTrue(recoveryHandler.recovered());
        assertTrue(recoveryHandler.newExecuteLanded());
        invariant_stateTracksRecoveryAndExecute();
        invariant_bitmapTracksCurrentEpoch();
        invariant_replacementTreesSpent();
    }

    function invariant_stateTracksRecoveryAndExecute() public view {
        bool recovered = recoveryHandler.recovered();
        bool executed = recoveryHandler.newExecuteLanded();
        assertFalse(executed && !recovered, "new key executed before recovery");
        assertEq(wallet.owner(), OWNER, "recovery changed owner");
        assertEq(factory.walletOwner(WALLET), OWNER, "factory owner drifted");
        assertEq(wallet.keyVersion(), recovered ? 1 : 0, "epoch drifted");
        assertEq(
            wallet.actionNonce(),
            initialNonce + 1 + (recovered ? 1 : 0) + (executed ? 1 : 0),
            "nonce drifted"
        );
        assertEq(
            wallet.getShrincsPublicKeyCommitment(),
            recovered ? recoveredCommitment : mainCommitment,
            "main commitment drifted"
        );
        assertEq(
            wallet.getErc1271PublicKeyCommitment(),
            erc1271Commitment,
            "1271 commitment drifted"
        );
        assertEq(wallet.maxSignatures(), MAX_SIG, "leaf budget drifted");
        assertEq(
            WALLET.balance,
            WALLET_FUNDS - (executed ? NEW_TRANSFER : 0),
            "wallet balance drifted"
        );
        assertEq(_oldSink().balance, 0, "old-key transfer landed");
        assertEq(
            _newSink().balance,
            executed ? NEW_TRANSFER : 0,
            "new-key transfer drifted"
        );
    }

    function invariant_bitmapTracksCurrentEpoch() public view {
        bool recovered = recoveryHandler.recovered();
        bool executed = recoveryHandler.newExecuteLanded();
        uint256 expectedUsed = recovered ? (executed ? 1 : 0) : 1;
        assertEq(
            wallet.statefulLeavesUsed(),
            expectedUsed,
            "used count drifted"
        );
        assertEq(
            wallet.remainingStatefulSignatures(),
            MAX_SIG - expectedUsed,
            "remaining count drifted"
        );
        for (uint32 leaf = 0; leaf <= MAX_SIG + 1; leaf++) {
            bool expected = recovered
                ? executed && leaf == SIGN_BASE + 3
                : leaf == SIGN_BASE + 1;
            assertEq(
                wallet.isStatefulLeafUsed(leaf),
                expected,
                "current epoch bitmap drifted"
            );
        }
    }

    function invariant_replacementTreesSpent() public view {
        bool recovered = recoveryHandler.recovered();
        assertEq(
            wallet.harness_isStatefulTreeSpent(recoveredStatefulTree),
            recovered,
            "replacement stateful tree registry drifted"
        );
        assertEq(
            wallet.harness_isStatelessTreeSpent(recoveredStatelessTree),
            recovered,
            "replacement stateless tree registry drifted"
        );
    }
}
