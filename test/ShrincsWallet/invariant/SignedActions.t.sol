// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {SHRINCS} from "@quip.network/hashsigs-solidity-0.2.0/contracts/SHRINCS.sol";
import {SPHINCSPlusC} from "@quip.network/hashsigs-solidity-0.2.0/contracts/SPHINCSPlusC.sol";
import {SHRINCSTestSigner} from "@quip.network/hashsigs-solidity-0.2.0/test/helpers/SHRINCSTestSigner.sol";
import {HashSuite} from "shrincs-hash/HashSuite.sol";
import {ShrincsWalletTest} from "../ShrincsWallet.t.sol";
import {ShrincsWalletCodec as Codec} from "../../../contracts/shrincs/ShrincsWalletCodec.sol";
import {IShrincsWallet} from "../../../contracts/shrincs/interfaces/IShrincsWallet.sol";
import {ShrincsWalletSignedActionsHandler, SignedActionsEntryPoint} from "./support/SignedActionsHandler.t.sol";

/// forge-config: default.invariant.runs = 8
/// forge-config: default.invariant.depth = 16
/// forge-config: default.invariant.fail-on-revert = true

contract ShrincsWallet_SignedActions_Invariant is ShrincsWalletTest {
    uint256 internal constant SET_KEY = 0;
    uint256 internal constant WITHDRAW = 1;
    uint256 internal constant OLD_SIGNATURE = 0;
    uint256 internal constant NEW_SIGNATURE = 1;
    uint256 internal constant INITIAL_DEPOSIT = 0.6 ether;
    uint256 internal constant WITHDRAWAL = 0.2 ether;
    bytes32 internal constant ERC1271_HASH =
        keccak256("signed-actions-erc1271");
    address internal constant RECIPIENT = address(0xD00D);

    ShrincsWalletSignedActionsHandler public signedHandler;
    SHRINCS.PublicKey internal nextErc1271Key;
    bytes32 internal nextErc1271Commitment;
    uint256 internal initialNonce;

    function _signAction(
        bytes32 action,
        bytes32 payload,
        uint256 nonce,
        uint32 leaf
    ) internal view returns (SHRINCS.Signature memory) {
        SHRINCS.ActionContext memory context = Codec.buildActionContext(
            wallet.exposed_shrincsDomainSeparator(),
            nonce,
            0,
            action,
            payload
        );
        return _signStatefulActionWith(mainKey, mainCommitment, context, leaf);
    }

    function _newErc1271Signature(
        SHRINCS.SigningKey memory key,
        uint256 nonce
    ) internal returns (bytes memory) {
        SHRINCS.ActionContext memory context = Codec.buildActionContext(
            wallet.exposed_shrincsDomainSeparator(),
            nonce,
            0,
            Codec.ACTION_ERC1271,
            ERC1271_HASH
        );
        bytes memory message = abi.encodePacked(
            SHRINCS.statelessRawMessageHash(
                nextErc1271Commitment,
                SHRINCS.statelessActionMessageHash(
                    nextErc1271Commitment,
                    context
                )
            )
        );
        SPHINCSPlusC.Signature memory signature = _signStatelessRaw(
            key,
            nextErc1271Key,
            message
        );
        return abi.encode(nextErc1271Key, signature, _ownerEcdsa(ERC1271_HASH));
    }

    function setUp() public override {
        super.setUp();
        initialNonce = wallet.actionNonce();

        SignedActionsEntryPoint entryPoint = new SignedActionsEntryPoint();
        vm.etch(ENTRY_POINT, address(entryPoint).code);
        vm.deal(address(this), INITIAL_DEPOSIT);
        SignedActionsEntryPoint(ENTRY_POINT).depositFor{value: INITIAL_DEPOSIT}(
            WALLET
        );

        (
            SHRINCS.SigningKey memory nextKey,
            SHRINCS.PublicKey memory publicKey,
            bool generated
        ) = SHRINCSTestSigner.keygen("signed-actions-new-erc1271", MAX_SIG);
        require(generated, "new erc1271 keygen");
        nextErc1271Key = publicKey;
        nextErc1271Commitment = _commitment32(publicKey);

        bytes[] memory actions = new bytes[](2);
        actions[SET_KEY] = abi.encodeCall(
            IShrincsWallet.setErc1271Key,
            (
                _mainPk(),
                _signAction(
                    Codec.ACTION_SET_ERC1271_KEY,
                    Codec.setErc1271KeyPayloadHash(
                        nextErc1271Commitment,
                        HashSuite.HASH_SUITE_ID
                    ),
                    initialNonce,
                    SIGN_BASE + 1
                ),
                nextErc1271Key,
                HashSuite.HASH_SUITE_ID
            )
        );
        actions[WITHDRAW] = abi.encodeCall(
            IShrincsWallet.withdrawDepositTo,
            (
                _mainPk(),
                _signAction(
                    Codec.ACTION_WITHDRAW,
                    Codec.withdrawPayloadHash(RECIPIENT, WITHDRAWAL),
                    initialNonce + 1,
                    SIGN_BASE + 2
                ),
                RECIPIENT,
                WITHDRAWAL
            )
        );

        bytes[] memory signatures = new bytes[](2);
        signatures[OLD_SIGNATURE] = abi.encode(
            erc1271Pk,
            _signErc1271(ERC1271_HASH),
            _ownerEcdsa(ERC1271_HASH)
        );
        signatures[NEW_SIGNATURE] = _newErc1271Signature(
            nextKey,
            initialNonce + 1
        );

        signedHandler = new ShrincsWalletSignedActionsHandler();
        signedHandler.initialize(
            wallet,
            OWNER,
            actions,
            signatures,
            ERC1271_HASH
        );
        targetContract(address(signedHandler));
        bytes4[] memory selectors = new bytes4[](2);
        selectors[0] = ShrincsWalletSignedActionsHandler
            .fuzzReplayAction
            .selector;
        selectors[1] = ShrincsWalletSignedActionsHandler
            .fuzzCheckErc1271
            .selector;
        targetSelector(
            FuzzSelector({addr: address(signedHandler), selectors: selectors})
        );
    }

    function test_setUp() public view override {
        assertEq(wallet.getDeposit(), INITIAL_DEPOSIT);
        assertEq(wallet.getErc1271PublicKeyCommitment(), erc1271Commitment);
        assertEq(signedHandler.successfulActions(), 0);
    }

    function test_signedActions_landAndSupersedeErc1271Signatures() public {
        signedHandler.fuzzCheckErc1271(OLD_SIGNATURE);
        signedHandler.fuzzCheckErc1271(NEW_SIGNATURE);
        signedHandler.fuzzReplayAction(WITHDRAW);
        signedHandler.fuzzReplayAction(SET_KEY);
        signedHandler.fuzzCheckErc1271(OLD_SIGNATURE);
        signedHandler.fuzzCheckErc1271(NEW_SIGNATURE);
        signedHandler.fuzzReplayAction(SET_KEY);
        signedHandler.fuzzReplayAction(WITHDRAW);
        signedHandler.fuzzCheckErc1271(OLD_SIGNATURE);
        signedHandler.fuzzCheckErc1271(NEW_SIGNATURE);
        signedHandler.fuzzReplayAction(WITHDRAW);

        assertEq(signedHandler.successfulActions(), 2);
        invariant_noUnexpectedOutcome();
        invariant_stateMatchesSignedActions();
        invariant_leafBitmapMatchesSignedActions();
    }

    function invariant_noUnexpectedOutcome() public view {
        assertEq(
            signedHandler.unexpectedOutcomes(),
            0,
            "signed action or ERC-1271 result diverged"
        );
    }

    function invariant_stateMatchesSignedActions() public view {
        uint256 completed = signedHandler.successfulActions();
        assertLe(completed, 2);
        assertEq(
            wallet.actionNonce(),
            initialNonce + completed,
            "nonce diverged"
        );
        assertEq(wallet.keyVersion(), 0, "epoch changed");
        assertEq(
            wallet.getShrincsPublicKeyCommitment(),
            mainCommitment,
            "main commitment changed"
        );
        assertEq(
            wallet.getErc1271PublicKeyCommitment(),
            completed >= 1 ? nextErc1271Commitment : erc1271Commitment,
            "ERC-1271 commitment diverged"
        );
        assertEq(wallet.owner(), OWNER, "owner changed");
        assertEq(
            factory.walletOwner(WALLET),
            OWNER,
            "factory owner registry changed"
        );
        assertEq(
            wallet.getDeposit(),
            INITIAL_DEPOSIT - (completed == 2 ? WITHDRAWAL : 0),
            "deposit diverged"
        );
        assertEq(
            ENTRY_POINT.balance,
            INITIAL_DEPOSIT - (completed == 2 ? WITHDRAWAL : 0),
            "entry point funds diverged"
        );
        assertEq(
            RECIPIENT.balance,
            completed == 2 ? WITHDRAWAL : 0,
            "recipient balance diverged"
        );
        assertTrue(
            wallet.harness_isStatefulTreeSpent(
                _treeId(erc1271Pk.statefulPublicKey)
            ),
            "previous ERC-1271 stateful tree became reusable"
        );
        assertTrue(
            wallet.harness_isStatelessTreeSpent(_statelessId(erc1271Pk)),
            "previous ERC-1271 stateless tree became reusable"
        );
        assertEq(
            wallet.harness_isStatefulTreeSpent(
                _treeId(nextErc1271Key.statefulPublicKey)
            ),
            completed >= 1,
            "replacement stateful tree spend diverged"
        );
        assertEq(
            wallet.harness_isStatelessTreeSpent(_statelessId(nextErc1271Key)),
            completed >= 1,
            "replacement stateless tree spend diverged"
        );
    }

    function invariant_leafBitmapMatchesSignedActions() public view {
        uint256 completed = signedHandler.successfulActions();
        assertEq(wallet.statefulLeavesUsed(), completed, "used count diverged");
        assertEq(
            wallet.remainingStatefulSignatures(),
            MAX_SIG - completed,
            "remaining budget diverged"
        );
        for (uint32 leaf = 0; leaf <= MAX_SIG + 1; leaf++) {
            bool expected = (leaf == SIGN_BASE + 1 && completed >= 1) ||
                (leaf == SIGN_BASE + 2 && completed == 2);
            assertEq(
                wallet.isStatefulLeafUsed(leaf),
                expected,
                "leaf bitmap diverged"
            );
        }
    }
}
