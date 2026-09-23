// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {ShrincsWalletTest} from "../ShrincsWallet.t.sol";
import {ShrincsWalletValidationHandler} from "./ValidationHandler.t.sol";
import {ShrincsWalletCodec as Codec} from "../../../contracts/shrincs/ShrincsWalletCodec.sol";
import {SHRINCS} from "@quip.network/hashsigs-solidity-0.2.0/contracts/SHRINCS.sol";
import {ERC4337} from "solady-0.1.26/src/accounts/ERC4337.sol";

/// forge-config: default.invariant.runs = 8
/// forge-config: default.invariant.depth = 32

contract ShrincsWallet_Validation_Invariant is ShrincsWalletTest {
    uint256 internal constant CHAIN_LEN = 5;

    ShrincsWalletValidationHandler public valHandler;
    uint256 internal valInitialNonce;

    function _chainHash(uint256 k) internal pure returns (bytes32) {
        return keccak256(abi.encode("validation-chain", k));
    }

    function _signChainOp(
        uint32 k
    ) internal view returns (ERC4337.PackedUserOperation memory op) {
        bytes32 userOpHash = _chainHash(k);
        SHRINCS.ActionContext memory ctx = Codec.buildActionContext(
            wallet.exposed_shrincsDomainSeparator(),
            valInitialNonce + k,
            0,
            Codec.ACTION_ERC4337_EXECUTE,
            Codec.erc4337PayloadHash(userOpHash)
        );
        SHRINCS.Signature memory sig = _signStatefulActionWith(
            mainKey,
            mainCommitment,
            ctx,
            SIGN_BASE + 1 + k
        );
        op = _makeUserOp(_userOpBlob(sig, userOpHash));
    }

    function setUp() public override {
        super.setUp();
        valInitialNonce = wallet.actionNonce();
        valHandler = new ShrincsWalletValidationHandler();
        valHandler.initialize(wallet);
        for (uint32 k = 0; k < CHAIN_LEN; k++) {
            ERC4337.PackedUserOperation memory op = _signChainOp(k);
            valHandler.pushValidOp(op, _chainHash(k), SIGN_BASE + 1 + k);
        }
        valHandler.fuzzValidateReplay(0);
        valHandler.fuzzValidateReplay(0);
        targetContract(address(valHandler));
        bytes4[] memory selectors = new bytes4[](1);
        selectors[0] = ShrincsWalletValidationHandler
            .fuzzValidateReplay
            .selector;
        targetSelector(
            FuzzSelector({addr: address(valHandler), selectors: selectors})
        );
    }

    function test_setUp() public view override {
        assertEq(valHandler.poolLength(), CHAIN_LEN, "validation chain seeded");
        assertEq(valHandler.callsValidate(), 1, "seeded entry validated");
        assertEq(
            valHandler.staleUsedCount(),
            1,
            "seeded duplicate reported consumed leaf"
        );
        assertEq(
            wallet.actionNonce(),
            valInitialNonce + 1,
            "seeded validation advanced the nonce"
        );
        assertEq(
            wallet.statefulLeavesUsed(),
            1,
            "seeded validation consumed its leaf"
        );
        assertTrue(
            wallet.isStatefulLeafUsed(SIGN_BASE + 1),
            "seeded leaf marked"
        );
    }

    function invariant_nonceTracksSuccesses() public view {
        assertEq(
            wallet.actionNonce(),
            valInitialNonce + valHandler.callsValidate(),
            "nonce diverged from validation success count"
        );
    }

    function invariant_successesFormPrefix() public view {
        uint256 m = valHandler.successLength();
        assertEq(
            m,
            valHandler.callsValidate(),
            "success mirror diverged from counter"
        );
        assertEq(
            wallet.statefulLeavesUsed(),
            m,
            "used counter diverged from success count"
        );
        for (uint256 i = 0; i < m; i++) {
            uint256 idx = valHandler.successAt(i);
            assertLt(idx, m, "success outside the landed prefix");
            assertTrue(
                wallet.isStatefulLeafUsed(valHandler.entryLeaf(idx)),
                "landed entry leaf not marked"
            );
        }
    }

    function invariant_noBadReason() public view {
        assertEq(
            valHandler.badReasonCount(),
            0,
            "validation reported an unexpected reason"
        );
    }

    function invariant_validationTouchesNothingElse() public view {
        assertEq(wallet.owner(), OWNER, "wallet owner drifted");
        assertEq(
            wallet.keyVersion(),
            0,
            "keyVersion advanced without rotation"
        );
        assertEq(
            wallet.getShrincsPublicKeyCommitment(),
            mainCommitment,
            "main commitment drifted"
        );
        assertEq(wallet.maxSignatures(), MAX_SIG, "maxSignatures drifted");
    }
}
