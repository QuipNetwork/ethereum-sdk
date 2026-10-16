// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {Test} from "forge-std-1.14.0/Test.sol";
import {ShrincsWalletHarness} from "../../../harness/ShrincsWalletHarness.sol";
import {IShrincsWallet} from "../../../../contracts/shrincs/interfaces/IShrincsWallet.sol";

contract SignedActionsEntryPoint {
    mapping(address => uint256) internal deposits;

    function depositFor(address account) external payable {
        deposits[account] += msg.value;
    }

    function balanceOf(address account) external view returns (uint256) {
        return deposits[account];
    }

    function withdrawTo(address payable to, uint256 amount) external {
        deposits[msg.sender] -= amount;
        (bool sent, ) = to.call{value: amount}("");
        require(sent, "deposit transfer failed");
    }
}

contract ShrincsWalletSignedActionsHandler is Test {
    uint256 internal constant SET_KEY = 0;
    uint256 internal constant WITHDRAW = 1;
    uint256 internal constant OLD_SIGNATURE = 0;
    uint256 internal constant NEW_SIGNATURE = 1;
    uint256 internal constant BEFORE_ACTIONS = 0;
    uint256 internal constant AFTER_KEY_SET = 1;

    ShrincsWalletHarness internal wallet;
    address internal owner;
    bytes[] internal actions;
    bytes[] internal erc1271Signatures;
    bytes32 internal erc1271Hash;

    uint256 public successfulActions;
    uint256 public unexpectedOutcomes;

    function initialize(
        ShrincsWalletHarness wallet_,
        address owner_,
        bytes[] calldata actionCalls,
        bytes[] calldata signatures,
        bytes32 hash
    ) external {
        require(address(wallet) == address(0), "handler already initialized");
        require(
            actionCalls.length == 2 && signatures.length == 2,
            "expected two signed entries"
        );
        wallet = wallet_;
        owner = owner_;
        erc1271Hash = hash;
        for (uint256 i = 0; i < 2; i++) {
            actions.push(actionCalls[i]);
            erc1271Signatures.push(signatures[i]);
        }
    }

    function fuzzReplayAction(uint256 index) external {
        index = bound(index, SET_KEY, WITHDRAW);
        vm.prank(owner);
        (bool succeeded, bytes memory result) = address(wallet).call(
            actions[index]
        );
        if (index == successfulActions) {
            if (succeeded) {
                successfulActions++;
            } else {
                unexpectedOutcomes++;
            }
        } else {
            bytes4 expected = index > successfulActions
                ? IShrincsWallet.InvalidSignature.selector
                : index == SET_KEY
                    ? IShrincsWallet.StatefulTreeSpent.selector
                    : IShrincsWallet.StaleStatefulLeaf.selector;
            bytes4 actual;
            if (result.length >= 4) {
                assembly ("memory-safe") {
                    actual := mload(add(result, 0x20))
                }
            }
            if (succeeded || actual != expected) unexpectedOutcomes++;
        }
    }

    function fuzzCheckErc1271(uint256 index) external {
        index = bound(index, OLD_SIGNATURE, NEW_SIGNATURE);
        bytes4 expected = (index == OLD_SIGNATURE &&
            successfulActions == BEFORE_ACTIONS) ||
            (index == NEW_SIGNATURE && successfulActions == AFTER_KEY_SET)
            ? bytes4(0x1626ba7e)
            : bytes4(0xffffffff);
        try
            wallet.isValidSignature(erc1271Hash, erc1271Signatures[index])
        returns (bytes4 result) {
            if (result != expected) unexpectedOutcomes++;
        } catch {
            unexpectedOutcomes++;
        }
    }
}
