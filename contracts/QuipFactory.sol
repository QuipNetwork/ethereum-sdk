// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.28;

import "@quip.network/hashsigs-solidity/contracts/WOTSPlus.sol";
import "./QuipWallet.sol";

contract QuipFactory {
    address payable public admin;
    address public immutable wotsLibrary;
    uint256 public fee = 0;

    // eth address -> "salt" vaultId -> QuipWallet address
    mapping(address => mapping(bytes32 => address)) public quips;
    
    // Track vaultIds for each owner
    mapping(address => bytes32[]) public vaultIds;

    event QuipCreated(
        uint256 amount,
        uint256 when,
        bytes32 vaultId,
        address creator,
        WOTSPlus.WinternitzAddress pqPubkey,
        address quip
    );


    constructor(address payable initialOwner, address _wotsLibrary) payable {
        admin = initialOwner;
        wotsLibrary = _wotsLibrary;
    }

    /* NOTE: you can pregenerate the address as follows:
    bytes32 hash = keccak256(
        abi.encodePacked(
            bytes1(0xff),
            address(this),
            salt,
            keccak256(type(Lock).creationCode)
        )
    );
    address preAddr = address(uint160(uint(hash)));
    */
    function depositToWinternitz(bytes32 vaultId, address payable to,
        WOTSPlus.WinternitzAddress calldata pqTo) public payable returns (address) {

        address contractAddr;

        bytes memory quipWalletCode = abi.encodePacked(
            type(QuipWallet).creationCode,
            // Encode params for the constructor
            abi.encode(address(this), to)
        );

        uint256 contractValue = msg.value - fee;

        assembly {
            // code starts after the first 32 bytes...
            // https://ethereum-blockchain-developer.com/110-upgrade-smart-contracts/12-metamorphosis-create2/
            let code := add(0x20, quipWalletCode)
            let codeSize := mload(quipWalletCode)
            contractAddr := create2(0, code, codeSize, vaultId)

            // revert on failure
            if iszero(extcodesize(contractAddr)) {
                revert(0, 0)
            }
        }

        assert(contractAddr != address(0));
        QuipWallet(payable(contractAddr)).initialize(pqTo);
        payable(contractAddr).transfer(contractValue);
        quips[to][vaultId] = contractAddr;
        vaultIds[to].push(vaultId); 
        
        emit QuipCreated(msg.value, block.timestamp, vaultId, to, pqTo, contractAddr);

        return contractAddr;
    }

    function transferOwnership(address newOwner) public {
        require(msg.sender == admin, "You aren't the admin");
        admin = payable(newOwner);
    }

    function setFee(uint256 newFee) public {
        require(msg.sender == admin, "You aren't the admin");
        fee = newFee;
    }

    function withdraw(uint256 amount) public {
        require(msg.sender == admin, "You aren't the admin");
        require(address(this).balance >= amount, "Insufficient balance");
        admin.transfer(amount);
    }

    function owner() public view returns (address) {
        return admin;
    }

}
