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
import {Ownable} from "@openzeppelin-contracts-5.6.0-rc.1/access/Ownable.sol";
import {Ownable2Step} from "@openzeppelin-contracts-5.6.0-rc.1/access/Ownable2Step.sol";
import {SafeTransferLib} from "solady-0.1.26/src/utils/SafeTransferLib.sol";
import {EfficientHashLib} from "solady-0.1.26/src/utils/EfficientHashLib.sol";
import {LibCall} from "solady-0.1.26/src/utils/LibCall.sol";
import {Initializable} from "@openzeppelin-contracts-5.6.0-rc.1/proxy/utils/Initializable.sol";
import "./interfaces/IQuipWallet.sol";
import "./interfaces/IQuipFactory.sol";

contract QuipWallet is IQuipWallet, Ownable2Step, Initializable {
    /// @inheritdoc IQuipWallet
    address payable public quipFactory;
    /// @inheritdoc IQuipWallet
    WOTSPlus.WinternitzAddress public pqOwner;

    receive() external payable {}

    fallback() external payable {}

    constructor(address payable creator, address payable newOwner) payable Ownable(newOwner) {
        quipFactory = creator;
    }

    function renounceOwnership() public view override onlyOwner {
        revert RenounceDisabled();
    }

    /// @inheritdoc IQuipWallet
    function initialize(WOTSPlus.WinternitzAddress calldata newPqOwner) public initializer {
        if (msg.sender != owner() && msg.sender != quipFactory) revert UnauthorizedInitializer();
        if (newPqOwner.publicSeed == bytes32(0) || newPqOwner.publicKeyHash == bytes32(0)) revert InvalidPqOwner();
        pqOwner = newPqOwner;
    }

    /// @inheritdoc IQuipWallet
    function changePqOwner(
        WOTSPlus.WinternitzAddress calldata newPqOwner,
        WOTSPlus.WinternitzElements calldata pqSig
    ) public onlyOwner {
        bytes32 msgHash = EfficientHashLib.hash(
            pqOwner.publicSeed,
            pqOwner.publicKeyHash,
            newPqOwner.publicSeed,
            newPqOwner.publicKeyHash
        );

        WOTSPlus.WinternitzMessage memory message = WOTSPlus.WinternitzMessage({
            messageHash: msgHash
        });

        if (!WOTSPlus.verify(pqOwner, message, pqSig)) revert InvalidSignature();
        pqOwner = newPqOwner;
    }

    /// @inheritdoc IQuipWallet
    function transferWithWinternitz(
        WOTSPlus.WinternitzAddress calldata nextPqOwner,
        WOTSPlus.WinternitzElements calldata pqSig,
        address payable to,
        uint256 value
    ) public payable onlyOwner {
        WOTSPlus.WinternitzAddress memory curPqOwner = pqOwner;

        uint256 fee = getTransferFee();

        if (msg.value < fee) revert InsufficientFee(fee, msg.value);
        if (address(this).balance < value) revert InsufficientBalance(value, address(this).balance);

        bytes memory msgData = abi.encodePacked(
            pqOwner.publicSeed,
            pqOwner.publicKeyHash,
            nextPqOwner.publicSeed,
            nextPqOwner.publicKeyHash,
            to,
            value
        );

        WOTSPlus.WinternitzMessage memory message = WOTSPlus.WinternitzMessage({
            messageHash: keccak256(msgData)
        });

        if (!WOTSPlus.verify(pqOwner, message, pqSig)) revert InvalidSignature();
        pqOwner = nextPqOwner;

        SafeTransferLib.safeTransferETH(to, value);
        SafeTransferLib.safeTransferETH(quipFactory, fee);

        emit pqTransfer(value, block.timestamp, curPqOwner, nextPqOwner, to);
    }

    /// @inheritdoc IQuipWallet
    function executeWithWinternitz(
        WOTSPlus.WinternitzAddress calldata nextPqOwner,
        WOTSPlus.WinternitzElements calldata pqSig,
        address payable target,
        bytes calldata opdata
    ) public payable onlyOwner returns (bytes memory) {
        uint256 fee = getExecuteFee();
        if (msg.value < fee) revert InsufficientFee(fee, msg.value);

        uint256 forwardValue = msg.value - fee;

        WOTSPlus.WinternitzMessage memory message = WOTSPlus.WinternitzMessage({
            messageHash: keccak256(
                abi.encodePacked(
                    pqOwner.publicSeed,
                    pqOwner.publicKeyHash,
                    nextPqOwner.publicSeed,
                    nextPqOwner.publicKeyHash,
                    target,
                    opdata
                )
            )
        });

        if (!WOTSPlus.verify(pqOwner, message, pqSig)) revert InvalidSignature();
        pqOwner = nextPqOwner;
        SafeTransferLib.safeTransferETH(quipFactory, fee);

        // Reverts from `target` are bubbled up directly.
        return LibCall.callContract(target, forwardValue, opdata);
    }

    /// @inheritdoc IQuipWallet
    function getTransferFee() public view returns (uint256) {
        return IQuipFactory(quipFactory).transferFee();
    }

    /// @inheritdoc IQuipWallet
    function getExecuteFee() public view returns (uint256) {
        return IQuipFactory(quipFactory).executeFee();
    }
}
