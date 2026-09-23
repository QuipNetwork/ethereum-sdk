// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {WalletFactoryTest} from "../WalletFactory.t.sol";
import {WalletFactory} from "../../../contracts/WalletFactory.sol";
import {CREATE3} from "solady-0.1.26/src/utils/CREATE3.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.2.0/contracts/WOTSPlus.sol";

contract WalletFactoryDeployHandler is WalletFactoryTest {
    struct DeployRecord {
        bytes32 commitment;
        address wallet;
        address to;
        uint256 fee;
        uint256 value;
        bool addrMatch;
    }

    WalletFactory internal factory_;
    address internal seedImpl;
    uint256 internal deployNonce;
    DeployRecord[] internal deploys;
    uint256 public expectedFactoryFees;
    bool public seedDeprecated;
    uint256 public callsDeploy;
    uint256 public callsDeploySpecific;
    uint256 public callsSetFee;
    uint256 public callsDeprecate;
    uint256 public callsUndeprecate;
    uint256 public revertCount;
    uint256 public lastSetFee;
    bool public feeEverSet;

    function initialize(WalletFactory factory__, address seedImpl_) external {
        require(address(factory_) == address(0), "handler already initialized");
        factory_ = factory__;
        seedImpl = seedImpl_;
        vm.deal(address(this), 10_000 ether);
    }

    function fuzzDeployLatest(uint256 ownerSalt, uint256 valueSalt) external {
        address to = address(uint160(bound(ownerSalt, 1, 5)));
        uint256 fee = factory_.creationFee();
        uint256 value;
        if (valueSalt % 8 == 0) {
            value = fee == 0 ? 0 : fee - 1;
        } else {
            value = bound(valueSalt, fee, fee + 2 ether);
        }
        bytes32 commitment = keccak256(abi.encode(deployNonce));
        deployNonce++;
        bytes memory payload = _deployPayload(deployNonce);
        try factory_.deployLatestWalletProxy{value: value}(commitment, payable(to), payload) returns (
            address wallet
        ) {
            callsDeploy++;
            expectedFactoryFees += fee;
            address predicted = _predictedWallet(commitment);
            deploys.push(
                DeployRecord({
                    commitment: commitment,
                    wallet: wallet,
                    to: to,
                    fee: fee,
                    value: value,
                    addrMatch: wallet == predicted
                })
            );
        } catch {
            revertCount++;
        }
    }

    function fuzzSetCreationFee(uint256 fee) external {
        fee = bound(fee, 0, factory_.MAX_FEE());
        try factory_.setCreationFee(fee) {
            callsSetFee++;
            lastSetFee = fee;
            feeEverSet = true;
        } catch {
            revertCount++;
        }
    }

    function fuzzDeploySpecific(uint256 idxSalt) external {
        uint256 count = factory_.getVettedCodeCount();
        if (count == 0) {
            revertCount++;
            return;
        }
        uint256 index = bound(idxSalt, 0, count - 1);
        address to = address(uint160(bound(idxSalt >> 128, 1, 5)));
        uint256 fee = factory_.creationFee();
        uint256 value = bound(idxSalt, fee, fee + 2 ether);
        bytes32 commitment = keccak256(abi.encode(deployNonce));
        deployNonce++;
        bytes memory payload = _deployPayload(deployNonce);
        try factory_.deploySpecificWalletProxy{value: value}(commitment, index, payable(to), payload) returns (
            address wallet
        ) {
            callsDeploySpecific++;
            expectedFactoryFees += fee;
            deploys.push(
                DeployRecord({
                    commitment: commitment,
                    wallet: wallet,
                    to: to,
                    fee: fee,
                    value: value,
                    addrMatch: wallet == _predictedWallet(commitment)
                })
            );
        } catch {
            revertCount++;
        }
    }

    function fuzzDeprecateSeed() external {
        try factory_.deprecateImplementation(seedImpl) {
            callsDeprecate++;
            seedDeprecated = true;
        } catch {
            revertCount++;
        }
    }

    function fuzzUndeprecateSeed() external {
        try factory_.undeprecateImplementation(seedImpl) {
            callsUndeprecate++;
            seedDeprecated = false;
        } catch {
            revertCount++;
        }
    }

    function deployCount() external view returns (uint256) {
        return deploys.length;
    }

    function deployAt(uint256 i) external view returns (DeployRecord memory) {
        return deploys[i];
    }

    function _deployPayload(uint256 nonce_) internal pure returns (bytes memory) {
        bytes32 vaultSeed = keccak256(abi.encode(nonce_, "vault"));
        (
            WOTSPlus.WinternitzAddress[10] memory txnPubkeys,
            bytes32[10] memory txnPrivkeys
        ) = _generateTransactionKeys(vaultSeed);
        WOTSPlus.WinternitzAddress[] memory recoveryPubkeys = _generateRecoveryKeys(txnPrivkeys[0], 10);
        return _buildInitPayloadForCreate(vaultSeed, txnPubkeys, recoveryPubkeys);
    }

    function _predictedWallet(bytes32 commitment) internal view returns (address) {
        return CREATE3.predictDeterministicAddress(commitment, address(factory_));
    }
}
