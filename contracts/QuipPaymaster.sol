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

import {Ownable} from "solady-0.1.26/src/auth/Ownable.sol";
import {UUPSUpgradeable} from "solady-0.1.26/src/utils/UUPSUpgradeable.sol";
import {EIP712} from "solady-0.1.26/src/utils/EIP712.sol";
import {Initializable} from "solady-0.1.26/src/utils/Initializable.sol";
import {ECDSA} from "solady-0.1.26/src/utils/ECDSA.sol";
import {IPaymaster, IEntryPointStake, PackedUserOperation} from
    "@openzeppelin-contracts-5.6.0-rc.1/interfaces/draft-IERC4337.sol";
import {IQuipPaymaster} from "./interfaces/IQuipPaymaster.sol";
import {QuipPaymasterStorage as Storage} from "./storage/QuipPaymasterStorage.sol";

/// @title QuipPaymaster
/// @dev A UUPS-upgradeable ERC-4337 verifying paymaster. Validates an off-chain EIP-712
///      signature from a trusted backend signer to authorize gas sponsorship for QuipWallet
///      UserOperations. Designed for future extension to ERC-20 token acceptance via upgrade.
contract QuipPaymaster is IQuipPaymaster, Ownable, UUPSUpgradeable, EIP712, Initializable {
    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                          CONSTANTS                            */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev ERC-4337 v0.7 EntryPoint singleton address.
    address public constant ENTRY_POINT = 0x0000000071727De22E5E9d8BAf0edAc6f37da032;

    /// @dev Offset into `paymasterAndData` where custom paymaster data begins.
    ///      [0:20) paymaster address, [20:36) verificationGasLimit, [36:52) postOpGasLimit.
    uint256 private constant _PAYMASTER_DATA_OFFSET = 52;

    /// @dev EIP-712 typehash for the paymaster approval struct.
    ///      PaymasterApproval(bytes32 userOpHash,uint48 validUntil,uint48 validAfter)
    bytes32 private constant _APPROVAL_TYPEHASH =
        0xcab5f0c894217ba58612fbb849582d4d783aa8010bf16f7b225d77043422d94b;

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                         CONSTRUCTOR                           */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    constructor() {
        _disableInitializers();
    }

    /// @dev Accept ETH deposits.
    receive() external payable {}

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                      INTERNAL OVERRIDES                       */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Guard owner initialization to prevent re-initialization.
    function _guardInitializeOwner() internal pure override returns (bool) {
        return true;
    }

    /// @dev Restrict upgrades to the contract owner.
    function _authorizeUpgrade(address) internal override onlyOwner {}

    /// @dev EIP-712 domain name and version for signature verification.
    function _domainNameAndVersion()
        internal
        pure
        override
        returns (string memory name, string memory version)
    {
        name = "QuipPaymaster";
        version = "1";
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                      EXTERNAL FUNCTIONS                       */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @inheritdoc IQuipPaymaster
    function initialize(address owner_, address verifier_) external initializer {
        if (owner_ == address(0)) revert ZeroAddressOwner();
        if (verifier_ == address(0)) revert ZeroAddressVerifier();
        _initializeOwner(owner_);
        Storage.layout().verifier = verifier_;
        emit PaymasterInitialized(owner_, verifier_);
    }

    /// @inheritdoc IPaymaster
    function validatePaymasterUserOp(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash,
        uint256 /* maxCost */
    ) external override returns (bytes memory context, uint256 validationData) {
        if (msg.sender != ENTRY_POINT) revert InvalidEntryPoint();

        // Decode custom paymaster data from paymasterAndData[52:].
        // [52:58) validUntil (uint48), [58:64) validAfter (uint48), [64:end) ECDSA signature.
        uint48 validUntil = uint48(bytes6(userOp.paymasterAndData[_PAYMASTER_DATA_OFFSET:_PAYMASTER_DATA_OFFSET + 6]));
        uint48 validAfter = uint48(bytes6(userOp.paymasterAndData[_PAYMASTER_DATA_OFFSET + 6:_PAYMASTER_DATA_OFFSET + 12]));
        bytes calldata signature = userOp.paymasterAndData[_PAYMASTER_DATA_OFFSET + 12:];

        // Build EIP-712 digest and recover the signer.
        bytes32 structHash = keccak256(abi.encode(_APPROVAL_TYPEHASH, userOpHash, validUntil, validAfter));
        bytes32 digest = _hashTypedData(structHash);
        address recovered = ECDSA.recoverCalldata(digest, signature);

        if (recovered != Storage.layout().verifier) {
            return ("", 1);
        }

        // Pack validationData: [0:160) authorizer=0, [160:208) validUntil, [208:256) validAfter.
        validationData = (uint256(validUntil) << 160) | (uint256(validAfter) << 208);
        context = "";
    }

    /// @inheritdoc IPaymaster
    function postOp(
        PostOpMode,
        bytes calldata,
        uint256,
        uint256
    ) external override {
        if (msg.sender != ENTRY_POINT) revert InvalidEntryPoint();
    }

    /// @inheritdoc IQuipPaymaster
    function setVerifier(address newVerifier) external onlyOwner {
        if (newVerifier == address(0)) revert ZeroAddressVerifier();
        Storage.Layout storage $ = Storage.layout();
        address oldVerifier = $.verifier;
        $.verifier = newVerifier;
        emit VerifierUpdated(oldVerifier, newVerifier);
    }

    /// @inheritdoc IQuipPaymaster
    function deposit() external payable {
        IEntryPointStake(ENTRY_POINT).depositTo{value: msg.value}(address(this));
    }

    /// @inheritdoc IQuipPaymaster
    function withdrawTo(address payable to, uint256 amount) external onlyOwner {
        IEntryPointStake(ENTRY_POINT).withdrawTo(to, amount);
    }

    /// @inheritdoc IQuipPaymaster
    function addStake(uint32 unstakeDelaySec) external payable onlyOwner {
        IEntryPointStake(ENTRY_POINT).addStake{value: msg.value}(unstakeDelaySec);
    }

    /// @inheritdoc IQuipPaymaster
    function unlockStake() external onlyOwner {
        IEntryPointStake(ENTRY_POINT).unlockStake();
    }

    /// @inheritdoc IQuipPaymaster
    function withdrawStake(address payable to) external onlyOwner {
        IEntryPointStake(ENTRY_POINT).withdrawStake(to);
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                       VIEW FUNCTIONS                          */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @inheritdoc IQuipPaymaster
    function verifier() external view returns (address) {
        return Storage.layout().verifier;
    }

    /// @inheritdoc IQuipPaymaster
    function getDeposit() external view returns (uint256) {
        return IEntryPointStake(ENTRY_POINT).balanceOf(address(this));
    }
}
