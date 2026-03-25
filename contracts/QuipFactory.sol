// Copyright (C) 2025 quip.network
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import "@quip.network/hashsigs-solidity-0.1.0/contracts/WOTSPlus.sol";
import {Ownable as OZOwnable} from "@openzeppelin-contracts-5.6.0-rc.1/access/Ownable.sol";
import {Ownable2Step} from "@openzeppelin-contracts-5.6.0-rc.1/access/Ownable2Step.sol";
import {CREATE3} from "solady-0.1.26/src/utils/CREATE3.sol";
import {SafeTransferLib} from "solady-0.1.26/src/utils/SafeTransferLib.sol";
import "./interfaces/IQuipFactory.sol";
import "./QuipWallet.sol";

contract QuipFactory is IQuipFactory, Ownable2Step {
    /// @inheritdoc IQuipFactory
    address public immutable wotsLibrary;

    /// @inheritdoc IQuipFactory
    uint256 public immutable MAX_FEE;

    /// @inheritdoc IQuipFactory
    uint256 public creationFee = 0;
    /// @inheritdoc IQuipFactory
    uint256 public transferFee = 0;
    /// @inheritdoc IQuipFactory
    uint256 public executeFee = 0;

    /// @inheritdoc IQuipFactory
    mapping(address => mapping(bytes32 => address)) public quips;

    /// @inheritdoc IQuipFactory
    mapping(address => bytes32[]) public vaultIds;

    receive() external payable {}

    fallback() external payable {}

    constructor(address payable initialOwner, address _wotsLibrary, uint256 _maxFee) payable OZOwnable(initialOwner) {
        wotsLibrary = _wotsLibrary;
        MAX_FEE = _maxFee;
    }

    /// @inheritdoc IQuipFactory
    function depositToWinternitz(
        bytes32 vaultId,
        address payable to,
        WOTSPlus.WinternitzAddress calldata pqTo,
        WOTSPlus.WinternitzAddress[] calldata recoveryKeys
    ) public payable returns (address) {
        address contractAddr;

        bytes memory quipWalletCode = type(QuipWallet).creationCode;

        uint256 contractValue = msg.value - creationFee;

        contractAddr = CREATE3.deployDeterministic(quipWalletCode, vaultId);

        QuipWallet(payable(contractAddr)).initialize(payable(address(this)), to, pqTo, recoveryKeys);
        SafeTransferLib.safeTransferETH(contractAddr, contractValue);
        quips[to][vaultId] = contractAddr;
        vaultIds[to].push(vaultId);

        emit QuipCreated(
            msg.value,
            block.timestamp,
            vaultId,
            to,
            pqTo,
            contractAddr
        );

        return contractAddr;
    }

    /// @inheritdoc IQuipFactory
    function setCreationFee(uint256 newFee) public onlyOwner {
        if (newFee > MAX_FEE) revert FeeExceedsMax(newFee, MAX_FEE);
        creationFee = newFee;
    }

    /// @inheritdoc IQuipFactory
    function setTransferFee(uint256 newFee) public onlyOwner {
        if (newFee > MAX_FEE) revert FeeExceedsMax(newFee, MAX_FEE);
        transferFee = newFee;
    }

    /// @inheritdoc IQuipFactory
    function setExecuteFee(uint256 newFee) public onlyOwner {
        if (newFee > MAX_FEE) revert FeeExceedsMax(newFee, MAX_FEE);
        executeFee = newFee;
    }

    /// @inheritdoc IQuipFactory
    function withdraw(uint256 amount) public onlyOwner {
        if (address(this).balance < amount) revert InsufficientBalance(amount, address(this).balance);
        SafeTransferLib.forceSafeTransferETH(owner(), amount);
    }
}
