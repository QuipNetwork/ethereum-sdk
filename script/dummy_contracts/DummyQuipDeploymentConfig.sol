// SPDX-License-Identifier: MIT
pragma solidity ^0.8.33;

import {DummyQuipERC20} from "../../contracts/dummy_contracts/DummyQuipERC20.sol";
import {DummyQuipERC721} from "../../contracts/dummy_contracts/DummyQuipERC721.sol";
import {DummyQuipERC1155} from "../../contracts/dummy_contracts/DummyQuipERC1155.sol";
import {DummyQuipArbitraryCall} from
    "../../contracts/dummy_contracts/DummyQuipArbitraryCall.sol";

/// @notice Centralized salts and CREATE3 creation code for the active DummyQuip token suite.
/// @dev Other dummy contracts have been moved to `_archive/` and are no longer deployed.
library DummyQuipDeploymentConfig {
    function saltERC20SixDecimals() internal pure returns (bytes32) {
        return keccak256(bytes("quip.dummy.DummyQuipERC20SixDecimals.v1"));
    }

    function saltERC20EighteenDecimals() internal pure returns (bytes32) {
        return keccak256(bytes("quip.dummy.DummyQuipERC20EighteenDecimals.v1"));
    }

    function saltERC721() internal pure returns (bytes32) {
        // v2: mint API simplified to `mint(address) returns (uint256)` — no `amount` param.
        return keccak256(bytes("quip.dummy.DummyQuipERC721.v2"));
    }

    function saltERC1155() internal pure returns (bytes32) {
        // v2: closed token-id set {1, 2}; `mintOne` / `mintTwo` instead of generic `mint`.
        return keccak256(bytes("quip.dummy.DummyQuipERC1155.v2"));
    }

    function saltArbitraryCall() internal pure returns (bytes32) {
        return keccak256(bytes("quip.dummy.DummyQuipArbitraryCall.v1"));
    }

    function codeERC20SixDecimals() internal pure returns (bytes memory) {
        return abi.encodePacked(
            type(DummyQuipERC20).creationCode,
            abi.encode("DummyQuip ERC20 Six Decimals", "tQ6", uint8(6))
        );
    }

    function codeERC20EighteenDecimals() internal pure returns (bytes memory) {
        return abi.encodePacked(
            type(DummyQuipERC20).creationCode,
            abi.encode("DummyQuip ERC20 Eighteen Decimals", "tQ18", uint8(18))
        );
    }

    function codeERC721() internal pure returns (bytes memory) {
        return abi.encodePacked(
            type(DummyQuipERC721).creationCode,
            abi.encode("DummyQuip NFT", "tQNFT")
        );
    }

    function codeERC1155() internal pure returns (bytes memory) {
        return abi.encodePacked(
            type(DummyQuipERC1155).creationCode,
            abi.encode("ipfs://dummy-quip-erc1155/{id}.json")
        );
    }

    function codeArbitraryCall() internal pure returns (bytes memory) {
        // No constructor args — empty creation code is just the bytecode.
        return type(DummyQuipArbitraryCall).creationCode;
    }
}
