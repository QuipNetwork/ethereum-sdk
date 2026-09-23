// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {Test} from "forge-std-1.14.0/Test.sol";
import {WalletFactory} from "../../../contracts/WalletFactory.sol";

contract FactoryImplStub {
    uint256 public immutable id;

    constructor(uint256 id_) {
        id = id_;
    }
}

contract WalletFactoryInvariantHandler is Test {
    WalletFactory public factory;

    address[] internal originals;
    address[] internal twins;

    bool[] internal slotVetted;

    bytes32[] internal everVettedCodehashes;
    mapping(bytes32 => bool) internal codehashSeen;
    mapping(bytes32 => bool) internal expectedDeprecated;
    mapping(bytes32 => address) internal expectedImplementation;

    uint256 public callsVet;
    uint256 public callsDeprecate;
    uint256 public callsUndeprecate;
    uint256 public callsSetCreationFee;
    uint256 public callsSetExecuteFee;
    uint256 public expectedCreationFee;
    uint256 public expectedExecuteFee;
    uint256 public revertCount;
    uint256 public unexpectedSuccesses;
    uint256 public unexpectedFailures;

    function initialize(
        WalletFactory factory_,
        address initialImpl_,
        address[] calldata originals_,
        address[] calldata twins_
    ) external {
        require(address(factory) == address(0), "handler already initialized");
        require(originals_.length == twins_.length, "pool length mismatch");
        factory = factory_;
        for (uint256 i = 0; i < originals_.length; i++) {
            originals.push(originals_[i]);
            twins.push(twins_[i]);
            slotVetted.push(false);
        }
        _markCodehash(initialImpl_.codehash);
        expectedImplementation[initialImpl_.codehash] = initialImpl_;
    }

    function _markCodehash(bytes32 codehash) internal {
        if (!codehashSeen[codehash]) {
            codehashSeen[codehash] = true;
            everVettedCodehashes.push(codehash);
        }
    }

    function fuzzVetImplementation(uint256 index) external {
        index = bound(index, 0, originals.length - 1);
        address implementation = originals[index];
        bool alreadyVetted = slotVetted[index];
        try factory.vetImplementation(implementation) {
            if (alreadyVetted) unexpectedSuccesses++;
            callsVet++;
            slotVetted[index] = true;
            _markCodehash(implementation.codehash);
            expectedImplementation[implementation.codehash] = implementation;
            expectedDeprecated[implementation.codehash] = false;
        } catch {
            revertCount++;
            if (!alreadyVetted) unexpectedFailures++;
        }
    }

    function fuzzDeprecateImplementation(uint256 index, bool useTwin) external {
        if (everVettedCodehashes.length == 0) {
            revertCount++;
            return;
        }
        index = bound(index, 0, everVettedCodehashes.length - 1);
        bytes32 codehash = everVettedCodehashes[index];
        address implementation;
        if (useTwin) {
            implementation = _findTwinForCodehash(codehash);
            if (implementation == address(0)) {
                implementation = factory.vettedWalletImpls(codehash);
            }
        } else {
            implementation = factory.vettedWalletImpls(codehash);
        }
        try factory.deprecateImplementation(implementation) {
            callsDeprecate++;
            expectedDeprecated[codehash] = true;
        } catch {
            revertCount++;
            unexpectedFailures++;
        }
    }

    function fuzzUndeprecateImplementation(
        uint256 index,
        bool useTwin
    ) external {
        if (everVettedCodehashes.length == 0) {
            revertCount++;
            return;
        }
        index = bound(index, 0, everVettedCodehashes.length - 1);
        bytes32 codehash = everVettedCodehashes[index];
        bool wasDeprecated = expectedDeprecated[codehash];
        address implementation;
        if (useTwin) {
            implementation = _findTwinForCodehash(codehash);
            if (implementation == address(0)) {
                implementation = factory.vettedWalletImpls(codehash);
            }
        } else {
            implementation = factory.vettedWalletImpls(codehash);
        }
        try factory.undeprecateImplementation(implementation) {
            if (!wasDeprecated) unexpectedSuccesses++;
            callsUndeprecate++;
            expectedDeprecated[codehash] = false;
            expectedImplementation[codehash] = implementation;
        } catch {
            revertCount++;
            if (wasDeprecated) unexpectedFailures++;
        }
    }

    function fuzzSetCreationFee(uint256 fee) external {
        fee = bound(fee, 0, factory.MAX_FEE());
        try factory.setCreationFee(fee) {
            callsSetCreationFee++;
            expectedCreationFee = fee;
        } catch {
            revertCount++;
            unexpectedFailures++;
        }
    }

    function fuzzSetExecuteFee(uint256 fee) external {
        fee = bound(fee, 0, factory.MAX_FEE());
        try factory.setExecuteFee(fee) {
            callsSetExecuteFee++;
            expectedExecuteFee = fee;
        } catch {
            revertCount++;
            unexpectedFailures++;
        }
    }

    function everVettedCount() external view returns (uint256) {
        return everVettedCodehashes.length;
    }

    function everVettedAt(uint256 i) external view returns (bytes32) {
        return everVettedCodehashes[i];
    }

    function deprecatedInMirror(bytes32 codehash) external view returns (bool) {
        return expectedDeprecated[codehash];
    }

    function implementationInMirror(
        bytes32 codehash
    ) external view returns (address) {
        return expectedImplementation[codehash];
    }

    function twinAt(uint256 index) external view returns (address) {
        return twins[index];
    }

    function _findTwinForCodehash(
        bytes32 codehash
    ) internal view returns (address) {
        for (uint256 i = 0; i < originals.length; i++) {
            if (slotVetted[i] && originals[i].codehash == codehash) {
                return twins[i];
            }
        }
        return address(0);
    }
}
