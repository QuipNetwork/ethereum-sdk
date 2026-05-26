// SPDX-License-Identifier: MIT
pragma solidity ^0.8.33;

/// @notice Minimal CREATE3 factory for deterministic test deployments.
/// @dev Same final address across chains requires the factory itself to live at the same address.
contract DummyQuipCreate3Factory {
    event DummyQuipCreate3Deployed(
        bytes32 indexed salt,
        address indexed deployed,
        address indexed proxy,
        bytes32 creationCodeHash
    );

    error DummyQuipProxyDeployFailed(bytes32 salt);
    error DummyQuipTargetDeployFailed(bytes32 salt);
    error DummyQuipAlreadyDeployed(address predicted);

    function deploy(bytes32 salt, bytes memory creationCode)
        external
        payable
        returns (address deployed)
    {
        deployed = getDeployed(salt);
        if (deployed.code.length != 0) revert DummyQuipAlreadyDeployed(deployed);

        bytes memory proxyCreationCode = type(DummyQuipCreate3Proxy).creationCode;
        address proxy;
        assembly {
            proxy := create2(0, add(proxyCreationCode, 0x20), mload(proxyCreationCode), salt)
        }
        if (proxy == address(0)) revert DummyQuipProxyDeployFailed(salt);

        deployed = DummyQuipCreate3Proxy(payable(proxy)).deploy{value: msg.value}(creationCode);
        if (deployed == address(0)) revert DummyQuipTargetDeployFailed(salt);

        emit DummyQuipCreate3Deployed(salt, deployed, proxy, keccak256(creationCode));
    }

    function getDeployed(bytes32 salt) public view returns (address deployed) {
        address proxy = getProxy(salt);
        deployed = address(uint160(uint256(keccak256(abi.encodePacked(hex"d694", proxy, hex"01")))));
    }

    function getProxy(bytes32 salt) public view returns (address proxy) {
        bytes32 proxyCreationCodeHash = keccak256(type(DummyQuipCreate3Proxy).creationCode);
        proxy = address(
            uint160(uint256(keccak256(abi.encodePacked(hex"ff", address(this), salt, proxyCreationCodeHash))))
        );
    }
}

contract DummyQuipCreate3Proxy {
    error DummyQuipCreateFailed();

    function deploy(bytes memory creationCode) external payable returns (address deployed) {
        assembly {
            deployed := create(callvalue(), add(creationCode, 0x20), mload(creationCode))
        }
        if (deployed == address(0)) revert DummyQuipCreateFailed();
    }

    receive() external payable {}
}
