// SPDX-License-Identifier: MIT
pragma solidity ^0.8.33;

import {DummyQuipERC20} from "../../contracts/dummy_contracts/DummyQuipERC20.sol";
import {DummyQuipERC20Spender} from "../../contracts/dummy_contracts/DummyQuipERC20Spender.sol";
import {DummyQuipPaymentReceiver} from "../../contracts/dummy_contracts/DummyQuipPaymentReceiver.sol";
import {DummyQuipNonPayableReceiver} from "../../contracts/dummy_contracts/DummyQuipNonPayableReceiver.sol";
import {DummyQuipRevertingReceiver} from "../../contracts/dummy_contracts/DummyQuipRevertingReceiver.sol";

library DummyQuipDeploymentConfig {
    function saltERC20SixDecimals() internal pure returns (bytes32) {
        return keccak256(bytes("quip.dummy.DummyQuipERC20SixDecimals.v1"));
    }

    function saltERC20EighteenDecimals() internal pure returns (bytes32) {
        return keccak256(bytes("quip.dummy.DummyQuipERC20EighteenDecimals.v1"));
    }

    function saltERC20Spender() internal pure returns (bytes32) {
        return keccak256(bytes("quip.dummy.DummyQuipERC20Spender.v1"));
    }

    function saltPaymentReceiver() internal pure returns (bytes32) {
        return keccak256(bytes("quip.dummy.DummyQuipPaymentReceiver.v1"));
    }

    function saltNonPayableReceiver() internal pure returns (bytes32) {
        return keccak256(bytes("quip.dummy.DummyQuipNonPayableReceiver.v1"));
    }

    function saltRevertingReceiver() internal pure returns (bytes32) {
        return keccak256(bytes("quip.dummy.DummyQuipRevertingReceiver.v1"));
    }

    function codeERC20SixDecimals(address owner) internal pure returns (bytes memory) {
        return abi.encodePacked(
            type(DummyQuipERC20).creationCode,
            abi.encode(
                "DummyQuip ERC20 Six Decimals",
                "tQ6",
                uint8(6),
                owner,
                true,
                uint256(10_000 * 10 ** 6)
            )
        );
    }

    function codeERC20EighteenDecimals(address owner) internal pure returns (bytes memory) {
        return abi.encodePacked(
            type(DummyQuipERC20).creationCode,
            abi.encode(
                "DummyQuip ERC20 Eighteen Decimals",
                "tQ18",
                uint8(18),
                owner,
                true,
                uint256(10_000 ether)
            )
        );
    }

    function codeERC20Spender() internal pure returns (bytes memory) {
        return type(DummyQuipERC20Spender).creationCode;
    }

    function codePaymentReceiver(address owner) internal pure returns (bytes memory) {
        return abi.encodePacked(type(DummyQuipPaymentReceiver).creationCode, abi.encode(owner));
    }

    function codeNonPayableReceiver() internal pure returns (bytes memory) {
        return type(DummyQuipNonPayableReceiver).creationCode;
    }

    function codeRevertingReceiver() internal pure returns (bytes memory) {
        return type(DummyQuipRevertingReceiver).creationCode;
    }
}
