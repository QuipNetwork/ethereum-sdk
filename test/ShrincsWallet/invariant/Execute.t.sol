// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {ShrincsWalletTest} from "../ShrincsWallet.t.sol";
import {ShrincsWalletExecuteHandler} from "./support/ExecuteHandler.t.sol";
import {ShrincsWalletCodec as Codec} from "../../../contracts/shrincs/ShrincsWalletCodec.sol";
import {SHRINCS} from "@quip.network/hashsigs-solidity-0.2.0/contracts/SHRINCS.sol";

/// forge-config: default.invariant.runs = 8
/// forge-config: default.invariant.depth = 32

contract ShrincsWallet_Execute_Invariant is ShrincsWalletTest {
    uint256 internal constant CHAIN_LEN = 5;
    uint256 internal constant WALLET_FUNDS = 10 ether;

    ShrincsWalletExecuteHandler public execHandler;
    uint256 internal execInitialNonce;

    function _chainSink(uint32 k) internal view returns (address) {
        return vm.addr(0xE000 + k);
    }

    function _chainValue(uint256 k) internal pure returns (uint256) {
        return 0.1 ether * (k + 1);
    }

    function _signChainEntry(
        uint32 k
    ) internal view returns (SHRINCS.Signature memory) {
        address target = _chainSink(k);
        uint256 value = _chainValue(k);
        bytes32 payloadHash = Codec.executePayloadHash(
            target,
            value,
            keccak256(""),
            0
        );
        SHRINCS.ActionContext memory ctx = Codec.buildActionContext(
            wallet.exposed_shrincsDomainSeparator(),
            execInitialNonce + k,
            0,
            Codec.ACTION_EXECUTE,
            payloadHash
        );
        return
            _signStatefulActionWith(
                mainKey,
                mainCommitment,
                ctx,
                SIGN_BASE + 1 + k
            );
    }

    function setUp() public override {
        super.setUp();
        execInitialNonce = wallet.actionNonce();
        execHandler = new ShrincsWalletExecuteHandler();
        execHandler.initialize(wallet, OWNER);
        vm.deal(WALLET, WALLET_FUNDS);
        for (uint32 k = 0; k < CHAIN_LEN; k++) {
            execHandler.pushValidExecute(
                _mainPk(),
                _signChainEntry(k),
                _chainSink(k),
                _chainValue(k),
                "",
                0,
                SIGN_BASE + 1 + k
            );
        }
        execHandler.fuzzExecuteReplay(0);
        execHandler.fuzzExecuteReplay(0);
        targetContract(address(execHandler));
        bytes4[] memory selectors = new bytes4[](1);
        selectors[0] = ShrincsWalletExecuteHandler.fuzzExecuteReplay.selector;
        targetSelector(
            FuzzSelector({addr: address(execHandler), selectors: selectors})
        );
    }

    function test_setUp() public view override {
        assertEq(execHandler.poolLength(), CHAIN_LEN, "execute chain seeded");
        assertEq(execHandler.callsExecute(), 1, "seeded entry landed");
        assertEq(
            execHandler.staleUsedCount(),
            1,
            "seeded duplicate reported consumed leaf"
        );
        assertEq(
            wallet.actionNonce(),
            execInitialNonce + 1,
            "seeded landing advanced the nonce"
        );
        assertEq(
            wallet.statefulLeavesUsed(),
            1,
            "seeded landing consumed its leaf"
        );
        assertTrue(
            wallet.isStatefulLeafUsed(SIGN_BASE + 1),
            "seeded leaf marked"
        );
        assertEq(
            WALLET.balance,
            WALLET_FUNDS - _chainValue(0),
            "wallet debited by seeded value"
        );
        assertEq(
            _chainSink(0).balance,
            _chainValue(0),
            "seeded value delivered"
        );
    }

    function invariant_nonceTracksSuccesses() public view {
        assertEq(
            wallet.actionNonce(),
            execInitialNonce + execHandler.callsExecute(),
            "nonce diverged from execute success count"
        );
    }

    function invariant_successesFormPrefix() public view {
        uint256 m = execHandler.successLength();
        assertEq(
            m,
            execHandler.callsExecute(),
            "success mirror diverged from counter"
        );
        assertEq(
            wallet.statefulLeavesUsed(),
            m,
            "used counter diverged from success count"
        );
        for (uint256 i = 0; i < m; i++) {
            uint256 idx = execHandler.successAt(i);
            assertLt(idx, m, "success outside the landed prefix");
            assertTrue(
                wallet.isStatefulLeafUsed(execHandler.entryLeaf(idx)),
                "landed entry leaf not marked"
            );
        }
    }

    function invariant_ethAccountingExact() public view {
        uint256 m = execHandler.successLength();
        uint256 spent;
        for (uint256 i = 0; i < m; i++) {
            spent += execHandler.entryValue(execHandler.successAt(i));
        }
        assertEq(
            WALLET.balance,
            WALLET_FUNDS - spent,
            "wallet balance diverged from landed values"
        );
        for (uint32 k = 0; k < CHAIN_LEN; k++) {
            uint256 expected = k < m ? execHandler.entryValue(k) : 0;
            assertEq(
                _chainSink(k).balance,
                expected,
                "sink balance diverged from landed prefix"
            );
        }
    }

    function invariant_noBadReason() public view {
        assertEq(
            execHandler.badReasonCount(),
            0,
            "execute reverted with an unexpected reason"
        );
    }

    function invariant_executeTouchesNothingElse() public view {
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
