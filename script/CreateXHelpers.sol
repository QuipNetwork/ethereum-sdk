// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {Script, console} from "forge-std-1.14.0/Script.sol";
import {CREATE3} from "solady-0.1.26/src/utils/CREATE3.sol";
import {ICreateX} from "pcaversaccio-createx-1.0.0/src/ICreateX.sol";
import {DeployConstants} from "./Constants.sol";

/**
 * @title CreateXHelpers
 * @dev Sender-guarded CREATE3 deployment straight through pcaversaccio's canonical
 *      CreateX singleton — the live system's ONLY deploy dependency (the in-repo
 *      `Deployer` hop is retired to `contracts/deprecated/`; the sunset WOTS+
 *      family still deploys through it).
 *
 *      Salt scheme (CreateX `_parseSalt` layout):
 *        rawSalt = bytes20(OPERATOR) ‖ 0x00 ‖ bytes11(keccak256(saltPreimage))
 *      - first 20 bytes == msg.sender → PERMISSIONED: only the operator can consume
 *        the salt, so canonical addresses cannot be squatted on fresh chains
 *        (CREATE3 ignores initcode — an unguarded salt would let anyone deploy
 *        arbitrary code at the canonical address first).
 *      - 21st byte 0x00 → NO cross-chain redeploy protection: `block.chainid` stays
 *        out of the derivation, so addresses are identical on every chain.
 *      - last 11 bytes carry the salt-string entropy (truncated keccak).
 *
 *      CreateX then derives:
 *        guardedSalt = keccak256(bytes32(operator) ‖ rawSalt)      (MsgSender+False branch)
 *        address     = CREATE3(CreateX, guardedSalt)
 *
 *      Consequence to keep loud: EVERY canonical address is a function of the
 *      operator address. The operator key must sign each canonical deploy on each
 *      chain, forever — guard it accordingly (env: `DEPLOY_OPERATOR`).
 *
 *      Prediction uses solady's pure `CREATE3.predictDeterministicAddress` with
 *      `deployer = CreateX` (CreateX uses the same CREATE3 proxy initcode), so
 *      predictions work with no RPC and no CreateX code present. Deploys call the
 *      real singleton and cross-check the predicted address.
 */
abstract contract CreateXHelpers is Script {
    /// @dev Canonical CreateX singleton (see `DeployConstants`), re-exposed
    ///      under its established name for inheritors.
    address internal constant CREATEX = DeployConstants.CREATEX;

    /// @dev ERC-1967 implementation slot, for the proxy anti-squat assertion.
    bytes32 internal constant ERC1967_IMPL_SLOT =
        0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;

    /// @dev Assemble the sender-guarded raw salt: operator (20) ‖ 0x00 ‖ entropy (11).
    function _rawSalt(address operator, bytes memory saltPreimage) internal pure returns (bytes32) {
        return
            bytes32(uint256(uint160(operator)) << 96) |
            (keccak256(saltPreimage) >> 168);
    }

    /// @dev Mirror of CreateX's `_guard` for the MsgSender + no-crosschain branch:
    ///      `_efficientHash(bytes32(uint256(uint160(msg.sender))), salt)`.
    function _guardedSalt(address operator, bytes32 rawSalt_) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(bytes32(uint256(uint160(operator))), rawSalt_));
    }

    /// @dev Predict the canonical address for (operator, saltPreimage). Pure math —
    ///      no RPC, no CreateX code needed.
    function _predictCreateX(address operator, bytes memory saltPreimage) internal pure returns (address) {
        return CREATE3.predictDeterministicAddress(_guardedSalt(operator, _rawSalt(operator, saltPreimage)), CREATEX);
    }

    /// @dev Idempotent sender-guarded CREATE3 deploy. Skips (loudly) when code
    ///      already exists at the canonical address — callers deploying proxies
    ///      should follow up with `_assertProxyImpl` so a squatted/foreign contract
    ///      cannot masquerade as ours. Requires the broadcaster to BE the operator
    ///      (CreateX reverts `InvalidSalt` otherwise; we check first for a clearer
    ///      error).
    function _createXDeploy(
        address operator,
        uint256 privateKey,
        bytes memory bytecode,
        bytes memory saltPreimage,
        string memory name
    ) internal returns (address deployed) {
        require(vm.addr(privateKey) == operator, string.concat(name, ": broadcaster is not DEPLOY_OPERATOR"));
        address expected = _predictCreateX(operator, saltPreimage);
        if (expected.code.length > 0) {
            console.log(string.concat("  - ", name, " already has code at"), expected);
            console.log("    (idempotent skip; verify it is the expected deployment)");
            return expected;
        }
        require(CREATEX.code.length > 0, "CreateX not deployed on this chain");
        vm.startBroadcast(privateKey);
        deployed = ICreateX(CREATEX).deployCreate3(_rawSalt(operator, saltPreimage), bytecode);
        vm.stopBroadcast();
        require(deployed == expected, string.concat(name, ": CREATE3 address mismatch"));
        console.log(string.concat("  - ", name, " deployed at"), deployed);
    }

    /// @dev Anti-squat check for ERC-1967 proxies: the code at `proxy` must point
    ///      at `impl`. Catches a foreign contract occupying the canonical proxy
    ///      address (the idempotent skip alone cannot).
    function _assertProxyImpl(address proxy, address impl, string memory name) internal view {
        require(
            address(uint160(uint256(vm.load(proxy, ERC1967_IMPL_SLOT)))) == impl,
            string.concat(name, ": proxy does not point at the expected implementation")
        );
    }
}
