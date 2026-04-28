// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {IQuipWallet} from "../../../contracts/interfaces/IQuipWallet.sol";

import {QuipWalletTest} from "../QuipWallet.t.sol";
import {DummyContract} from "../../../contracts/test/DummyContract.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.1.0/contracts/WOTSPlus.sol";
import {WOTSPlusCodec as Codec} from "../../../contracts/WOTSPlusCodec.sol";

/// @title QuipWallet Normal Operation Scenario Test
/// @dev Multi-step happy-path flow: deploy, fund, execute transfer,
///      execute contract call, rotate key, execute with rotated key.
contract QuipWallet_normalOperation is QuipWalletTest {
    DummyContract public dummy;

    /// @dev Tracks the current PQ owner key across lifecycle steps.
    WOTSPlus.WinternitzAddress internal currentPq;
    bytes32 internal currentPrivKey;

    function setUp() public override {
        super.setUp();
        dummy = new DummyContract();
    }

    /// @dev Execute an ETH transfer using the current PQ key, rotate to next.
    function _executeTransfer(
        address to,
        uint256 amount,
        bytes32 nextSeed
    ) internal returns (bytes32 nextPrivKey) {
        WOTSPlus.WinternitzAddress memory nextPq;
        (nextPq, nextPrivKey) = _generateKeyPair(nextSeed);

        uint256 fee = wallet.getExecuteFee();
        bytes32 msgHash = _buildExecuteMessageHash(
            address(wallet),
            currentPq,
            nextPq,
            to,
            amount,
            "",
            fee
        );
        WOTSPlus.WinternitzElements memory sig = _sign(currentPrivKey, msgHash);

        vm.prank(ALICE);
        wallet.execute(
            Codec.encodeExecute(currentPq, nextPq, sig, to, amount, "")
        );

        currentPq = nextPq;
        currentPrivKey = nextPrivKey;
    }

    /// @dev Execute a contract call using the current PQ key, rotate to next.
    function _executeCall(
        address target,
        uint256 value,
        bytes memory data,
        bytes32 nextSeed
    ) internal returns (bytes32 nextPrivKey) {
        WOTSPlus.WinternitzAddress memory nextPq;
        (nextPq, nextPrivKey) = _generateKeyPair(nextSeed);

        uint256 fee = wallet.getExecuteFee();
        bytes32 msgHash = _buildExecuteMessageHash(
            address(wallet),
            currentPq,
            nextPq,
            target,
            value,
            data,
            fee
        );
        WOTSPlus.WinternitzElements memory sig = _sign(currentPrivKey, msgHash);

        vm.prank(ALICE);
        wallet.execute(
            Codec.encodeExecute(currentPq, nextPq, sig, target, value, data)
        );

        currentPq = nextPq;
        currentPrivKey = nextPrivKey;
    }

    /// @dev Full happy path: deploy -> fund -> execute transfer -> execute contract call
    ///      -> execute another transfer (auth key has rotated implicitly across each step).
    function test_simulation_fullNormalOperation() public {
        // Step 1: Wallet already deployed and funded in setUp
        assertEq(wallet.owner(), ALICE);
        assertGt(address(wallet).balance, 0);
        currentPq = alicePubkey;
        currentPrivKey = alicePrivateKey;

        // Step 2: Execute a pure ETH transfer to BOB
        uint256 bobBalBefore = BOB.balance;
        _executeTransfer(BOB, 0.1 ether, "lifecycle-key-1");
        assertEq(BOB.balance, bobBalBefore + 0.1 ether);

        // Step 3: pqOwner should have rotated
        assertTrue(wallet.isKey(Codec.KeyType.Transaction, currentPq));

        // Step 4: Execute a contract call (setValue on DummyContract)
        bytes memory callData = abi.encodeWithSelector(
            DummyContract.setValueNoFee.selector,
            42
        );
        _executeCall(address(dummy), 0, callData, "lifecycle-key-2");
        assertEq(dummy.value(), 42);

        // Step 5: Execute another transfer; the auth key rotates implicitly.
        uint256 bobBalBefore2 = BOB.balance;
        _executeTransfer(BOB, 0.05 ether, "lifecycle-key-3");
        assertEq(BOB.balance, bobBalBefore2 + 0.05 ether);
    }
}
