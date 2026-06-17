// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {WOTSPlusImplementationTest} from "../WOTSPlusImplementation.t.sol";
import {WOTSPlusImplementation} from "../../../contracts/wots/WOTSPlusImplementation.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.1.0/contracts/WOTSPlus.sol";
import {WOTSPlusCodec as Codec} from "../../../contracts/wots/WOTSPlusCodec.sol";
import {IWOTSPlusImplementation} from "../../../contracts/wots/interfaces/IWOTSPlusImplementation.sol";
import {ERC4337} from "solady-0.1.26/src/accounts/ERC4337.sol";
import {Ownable as SoladyOwnable} from "solady-0.1.26/src/auth/Ownable.sol";

/// @dev First 4 bytes of revert data, or zero if shorter. Used by the
///      reentrant probes below to capture the inner revert selector
///      without bubbling, so the outer call can still complete and the
///      test can pin the exact failure reason.
function _firstSelector(bytes memory data) pure returns (bytes4 sel) {
    if (data.length < 4) return bytes4(0);
    /// @solidity memory-safe-assembly
    assembly {
        sel := mload(add(data, 32))
    }
}

/// @dev Malicious contract that attempts reentrancy via `receive()`. Stashes
///      the callback `msg.sender` and the inner revert selector so the test
///      can assert (a) the wallet was the caller, and (b) the inner re-entry
///      reverted with the SPECIFIC `Ownable.Unauthorized` selector — a future
///      change that loosened auth would flip the selector and fail the test.
contract ReentrantReceiver {
    WOTSPlusImplementation public target;
    bool public attacked;
    address public callbackSender;
    bytes4 public innerRevertSelector;

    constructor(WOTSPlusImplementation target_) {
        target = target_;
    }

    receive() external payable {
        if (!attacked) {
            attacked = true;
            callbackSender = msg.sender;

            try target.execute(bytes("")) {
                // Should not reach here — leave selector zero so test fails.
            } catch (bytes memory err) {
                innerRevertSelector = _firstSelector(err);
            }
        }
    }
}

/// @dev Malicious contract that attempts reentrancy via the contract-call
///      path (`fallback`). Mirrors `ReentrantReceiver` for the call entry.
contract ReentrantTarget {
    WOTSPlusImplementation public wallet;
    bool public attacked;
    address public callbackSender;
    bytes4 public innerRevertSelector;

    constructor(WOTSPlusImplementation wallet_) {
        wallet = wallet_;
    }

    fallback() external payable {
        if (!attacked) {
            attacked = true;
            callbackSender = msg.sender;

            try wallet.execute(bytes("")) {
                // Should not reach here — leave selector zero so test fails.
            } catch (bytes memory err) {
                innerRevertSelector = _firstSelector(err);
            }
        }
    }
}

/// @dev Cross-function probe: the outer call hits `execute(bytes)`; the
///      callback re-enters `executeBatch` (a different state-mutating entry
///      point). Documents that `onlyEntryPoint` blocks the cross-function
///      attempt at the `msg.sender` gate, before any signature/auth machinery
///      gets a chance to re-process state.
contract CrossFunctionReentrant {
    WOTSPlusImplementation public wallet;
    bool public attacked;
    bytes4 public innerRevertSelector;

    constructor(WOTSPlusImplementation wallet_) {
        wallet = wallet_;
    }

    fallback() external payable {
        if (!attacked) {
            attacked = true;
            ERC4337.Call[] memory calls = new ERC4337.Call[](0);
            try wallet.executeBatch(calls) {
                // Should not reach here.
            } catch (bytes memory err) {
                innerRevertSelector = _firstSelector(err);
            }
        }
    }
}

/// @dev Malicious batch target whose `trigger()` is called inside the outer
///      `executeBatch` and re-enters the wallet's `executeBatch` from inside
///      the loop. The inner caller is the wallet (not the EntryPoint), so
///      `onlyEntryPoint` rejects with `Unauthorized`.
contract ReentrantBatchTarget {
    WOTSPlusImplementation public wallet;
    bool public attacked;
    address public callbackSender;
    bytes4 public innerRevertSelector;

    constructor(WOTSPlusImplementation wallet_) {
        wallet = wallet_;
    }

    function trigger() external payable {
        if (!attacked) {
            attacked = true;
            callbackSender = msg.sender;
            ERC4337.Call[] memory calls = new ERC4337.Call[](0);
            try wallet.executeBatch(calls) {
                // Should not reach here.
            } catch (bytes memory err) {
                innerRevertSelector = _firstSelector(err);
            }
        }
    }
}

/// @dev Minimal mock of the v0.7 EntryPoint surface needed to drive
///      `withdrawDepositTo` end-to-end without a fork. `withdrawTo` is the
///      one method the wallet calls; the implementation forwards ETH to
///      `to` via `.call`, which is the user-controlled hop the recipient
///      contract gets to exploit. Any `msg.value` the wallet sends with the
///      call is stashed in `receive()` to keep the mock self-funding.
contract MockEntryPointForReentrancy {
    function withdrawTo(address payable to, uint256 amount) external {
        (bool ok, ) = to.call{value: amount}("");
        require(ok, "transfer failed");
    }

    receive() external payable {}
}

/// @dev Replay attacker for the `withdrawDepositTo` path. Owns its own
///      WOTSPlusImplementation (contract-owner pattern, mirroring
///      `test_execute_revertsWhen_targetReentersWithSamePayload`) so the
///      callback can satisfy `onlyOwner` on the inner re-entry. The actual
///      defense being tested is the `_verifyAndRotate` rotation: the inner
///      replay's `currentKey` was already removed from the keyset by the
///      outer call's rotation, so `_enforceContained` fires `UnknownKey`
///      before the WOTS+ verify even runs.
contract ReentrantWithdrawReplayer {
    WOTSPlusImplementation public wallet;
    bytes public payload;
    bool public attacked;
    bytes4 public innerRevertSelector;

    function setup(address payable wallet_, bytes calldata payload_) external {
        wallet = WOTSPlusImplementation(wallet_);
        payload = payload_;
    }

    function fire() external {
        wallet.withdrawDepositTo(payload);
    }

    receive() external payable {
        if (!attacked) {
            attacked = true;
            try wallet.withdrawDepositTo(payload) {
                // Should not reach here.
            } catch (bytes memory err) {
                innerRevertSelector = _firstSelector(err);
            }
        }
    }
}

/// @title Reentrancy Protection Tests
/// @dev Each test exercises a distinct reentrancy entry point. The
///      `behaviors/execute.t.sol` suite holds a stronger
///      `targetReentersWithSamePayload` test that exercises the rotation
///      defense itself (contract-owner pattern, lets the revert bubble);
///      this file complements it by covering the auth-gate defense across
///      the wallet's other reentrancy-exposed surfaces.
contract WOTSPlusImplementation_reentrancy is WOTSPlusImplementationTest {
    address constant ENTRY_POINT_ADDR =
        0x0000000071727De22E5E9d8BAf0edAc6f37da032;

    /// @dev Same-function reentrancy via the contract-call path. The callback
    ///      is invoked AS the wallet, so the re-entered `execute(bytes)`'s
    ///      `onlyOwner` check rejects with `Ownable.Unauthorized`.
    function test_reentrancy_executeTargetReenters() public {
        ReentrantTarget attacker = new ReentrantTarget(wallet);

        bytes memory callData = abi.encodeWithSignature("trigger()");
        (WOTSPlus.WinternitzAddress memory nextPubkey, ) = _generateKeyPair(
            "reentrant-exec"
        );

        bytes32 msgHash = _buildExecuteMessageHash(
            address(wallet),
            alicePubkey,
            nextPubkey,
            address(attacker),
            0,
            callData,
            0
        );
        WOTSPlus.WinternitzElements memory sig = _sign(
            alicePrivateKey,
            msgHash
        );

        vm.prank(ALICE);
        wallet.execute(
            Codec.encodeExecute(
                alicePubkey,
                nextPubkey,
                sig,
                address(attacker),
                0,
                callData
            )
        );

        assertTrue(attacker.attacked(), "callback was not triggered");
        // Pin the "why": the callback's caller is the wallet, so the
        // re-entered `execute(bytes)` hits `onlyOwner` and reverts.
        assertEq(
            attacker.callbackSender(),
            address(wallet),
            "callback msg.sender was not the wallet"
        );
        assertEq(
            attacker.innerRevertSelector(),
            SoladyOwnable.Unauthorized.selector,
            "inner re-entry must revert with Unauthorized"
        );

        // Outer call still rotated the auth key.
        assertTrue(wallet.isKey(Codec.KeyType.Transaction, nextPubkey));
    }

    /// @dev Same-function reentrancy via `receive()` on a transfer recipient.
    function test_reentrancy_transferRecipientReenters() public {
        ReentrantReceiver attacker = new ReentrantReceiver(wallet);

        uint256 transferAmount = 0.1 ether;
        (WOTSPlus.WinternitzAddress memory nextPubkey, ) = _generateKeyPair(
            "reentrant-transfer"
        );

        bytes32 msgHash = _buildExecuteMessageHash(
            address(wallet),
            alicePubkey,
            nextPubkey,
            address(attacker),
            transferAmount,
            "",
            0
        );
        WOTSPlus.WinternitzElements memory sig = _sign(
            alicePrivateKey,
            msgHash
        );

        vm.prank(ALICE);
        wallet.execute(
            Codec.encodeExecute(
                alicePubkey,
                nextPubkey,
                sig,
                address(attacker),
                transferAmount,
                ""
            )
        );

        assertTrue(attacker.attacked(), "callback was not triggered");
        assertEq(
            attacker.callbackSender(),
            address(wallet),
            "callback msg.sender was not the wallet"
        );
        assertEq(
            attacker.innerRevertSelector(),
            SoladyOwnable.Unauthorized.selector,
            "inner re-entry must revert with Unauthorized"
        );

        // Outer effects: rotation completed, recipient received funds.
        assertTrue(wallet.isKey(Codec.KeyType.Transaction, nextPubkey));
        assertEq(address(attacker).balance, transferAmount);
    }

    /// @dev Cross-function reentrancy: outer `execute(bytes)` callback tries
    ///      to invoke `executeBatch`. The inner call's caller is the wallet
    ///      itself (not the EntryPoint singleton), so `onlyEntryPoint` rejects
    ///      with `Ownable.Unauthorized` before any state is touched. Locks
    ///      down the auth-gate cross-function invariant: a future refactor
    ///      that loosened any state-mutating entry point's caller check would
    ///      flip the selector and fail this test.
    function test_reentrancy_crossFunction_executeToExecuteBatch() public {
        CrossFunctionReentrant attacker = new CrossFunctionReentrant(wallet);

        bytes memory callData = abi.encodeWithSignature("trigger()");
        (WOTSPlus.WinternitzAddress memory nextPubkey, ) = _generateKeyPair(
            "cross-fn-reentrant"
        );

        bytes32 msgHash = _buildExecuteMessageHash(
            address(wallet),
            alicePubkey,
            nextPubkey,
            address(attacker),
            0,
            callData,
            0
        );
        WOTSPlus.WinternitzElements memory sig = _sign(
            alicePrivateKey,
            msgHash
        );

        vm.prank(ALICE);
        wallet.execute(
            Codec.encodeExecute(
                alicePubkey,
                nextPubkey,
                sig,
                address(attacker),
                0,
                callData
            )
        );

        assertTrue(attacker.attacked(), "callback was not triggered");
        assertEq(
            attacker.innerRevertSelector(),
            SoladyOwnable.Unauthorized.selector,
            "executeBatch re-entry must revert with Unauthorized"
        );
        assertTrue(wallet.isKey(Codec.KeyType.Transaction, nextPubkey));
    }

    /// @dev Same-function reentrancy on `executeBatch`. The outer call is
    ///      driven from the EntryPoint's prank context; the malicious target
    ///      inside the batch tries to re-enter `executeBatch` itself, but
    ///      its `msg.sender` is the wallet (not the EntryPoint), so
    ///      `onlyEntryPoint` rejects with `Ownable.Unauthorized`. Real gap
    ///      relative to the prior test set, which only exercised
    ///      `execute(bytes)`.
    function test_reentrancy_executeBatchTargetReenters() public {
        ReentrantBatchTarget attacker = new ReentrantBatchTarget(wallet);

        ERC4337.Call[] memory calls = new ERC4337.Call[](1);
        calls[0] = ERC4337.Call({
            target: address(attacker),
            value: 0,
            data: abi.encodeWithSelector(ReentrantBatchTarget.trigger.selector)
        });

        vm.prank(ENTRY_POINT_ADDR);
        wallet.executeBatch(calls);

        assertTrue(attacker.attacked(), "callback was not triggered");
        assertEq(
            attacker.callbackSender(),
            address(wallet),
            "callback msg.sender was not the wallet"
        );
        assertEq(
            attacker.innerRevertSelector(),
            SoladyOwnable.Unauthorized.selector,
            "inner re-entry must revert with Unauthorized"
        );
    }

    /// @dev Reentrancy via `withdrawDepositTo`. The defense here is the
    ///      `_verifyAndRotate` rotation, NOT the auth gate: the wallet's
    ///      owner is the malicious replayer contract (contract-owner
    ///      pattern), so `onlyOwner` lets the inner replay through. The
    ///      rotation already removed `currentKey` from the transaction
    ///      keyset by the time the EntryPoint forwards ETH to the
    ///      replayer's `receive()`, so the inner replay's
    ///      `_enforceContained` fires `UnknownKey`.
    ///
    ///      A mock EntryPoint is etched at the canonical singleton address
    ///      — the local test stack has no real deposit, and the only
    ///      EntryPoint surface this path touches is `withdrawTo`.
    function test_reentrancy_withdrawDepositToRecipientReenters() public {
        // Etch the mock at the canonical singleton address and seed it. The
        // mock's `withdrawTo` is the only EntryPoint surface this test path
        // touches; the deposit is funded directly via `vm.deal` since the
        // mock has no real deposit accounting.
        MockEntryPointForReentrancy mock = new MockEntryPointForReentrancy();
        vm.etch(ENTRY_POINT_ADDR, address(mock).code);
        vm.deal(ENTRY_POINT_ADDR, 10 ether);

        // Deploy a wallet whose owner is the replayer contract — same
        // contract-owner pattern used by
        // `test_execute_revertsWhen_targetReentersWithSamePayload`. The
        // replayer needs ETH to fund its own wallet's initial deposit.
        ReentrantWithdrawReplayer replayer = new ReentrantWithdrawReplayer();
        vm.deal(address(replayer), 1 ether);
        (
            address rWalletAddr,
            WOTSPlus.WinternitzAddress memory rPubkey,
            bytes32 rPrivKey,

        ) = _createWallet(
                address(replayer),
                keccak256("reentrant-withdraw"),
                INITIAL_DEPOSIT
            );

        // Build the signed withdraw payload. `to` is the replayer so the
        // EntryPoint's `withdrawTo` triggers `receive()` on the same
        // contract that's about to attempt the inner replay.
        (WOTSPlus.WinternitzAddress memory rNextKey, ) = _generateKeyPair(
            "reentrant-withdraw-next"
        );
        uint256 amount = 0.05 ether;
        bytes32 digest = Codec.withdrawDepositDigest(
            rWalletAddr,
            block.chainid,
            rPubkey.publicSeed,
            rPubkey.publicKeyHash,
            rNextKey.publicSeed,
            rNextKey.publicKeyHash,
            address(replayer),
            amount
        );
        WOTSPlus.WinternitzElements memory sig = _sign(rPrivKey, digest);
        bytes memory payload = Codec.encodeWithdrawDeposit(
            rPubkey,
            rNextKey,
            sig,
            address(replayer),
            amount
        );

        replayer.setup(payable(rWalletAddr), payload);

        // Outer flow:
        //   replayer.fire() → wallet.withdrawDepositTo(P)
        //     wallet rotates rPubkey → rNextKey (Effect, before Interaction)
        //     wallet calls EntryPoint.withdrawTo(replayer, amount)
        //       mock EntryPoint .call's replayer with ETH (Interaction)
        //         replayer.receive() re-enters wallet.withdrawDepositTo(P)
        //           inner _verifyAndRotate reverts at _enforceContained
        //           because rPubkey was rotated out → UnknownKey (captured)
        //         receive() catches and stashes the inner selector
        //       mock returns to wallet
        //     wallet returns to replayer.fire()
        replayer.fire();

        assertTrue(replayer.attacked(), "callback was not triggered");
        assertEq(
            replayer.innerRevertSelector(),
            IWOTSPlusImplementation.UnknownKey.selector,
            "inner replay must revert with UnknownKey"
        );

        // Outer call's effects landed: replayer received the funds and the
        // wallet's auth key rotated to rNextKey.
        assertEq(address(replayer).balance, amount);
        assertTrue(
            WOTSPlusImplementation(payable(rWalletAddr)).isKey(
                Codec.KeyType.Transaction,
                rNextKey
            )
        );
        assertFalse(
            WOTSPlusImplementation(payable(rWalletAddr)).isKey(
                Codec.KeyType.Transaction,
                rPubkey
            )
        );
    }
}
