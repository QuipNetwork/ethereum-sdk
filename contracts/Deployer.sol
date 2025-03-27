// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.28;

// Deployer allows us to deploy contracts with consistent addresses across EVM chains
// using create2
contract Deployer {
    event Deploy(address addr);

    function deploy(bytes memory bytecode, uint256 salt) public returns (address) {
        address contractAddr;
        assembly {
            // code starts after the first 32 bytes...
            // https://ethereum-blockchain-developer.com/110-upgrade-smart-contracts/12-metamorphosis-create2/
            let code := add(0x20, bytecode)
            let codeSize := mload(bytecode)
            contractAddr := create2(callvalue(), code, codeSize, salt)

            // revert on failure
            if iszero(extcodesize(contractAddr)) {
                revert(0, 0)
            }
        }      
        emit Deploy(contractAddr);
        return contractAddr;
    }
}