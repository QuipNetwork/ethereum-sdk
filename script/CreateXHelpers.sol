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

    /// @dev Byte 20 of the raw salt is CreateX's CROSS-CHAIN FLAG, and it is the
    ///      difference between one canonical address everywhere and a different
    ///      address per chain:
    ///        0x01 → guard folds in `block.chainid`  (per-chain addresses)
    ///        0x00 → guard omits it                  (chain-invariant) ← always us
    ///      Chain-invariance is the entire point of the canonical address set, so
    ///      this is written explicitly below and asserted in `_assertSaltLayout`.
    uint256 internal constant CROSSCHAIN_FLAG_OFF = 0x00;

    /// @dev Placement shifts for the three raw-salt fields (bytes numbered from the
    ///      most-significant end, matching CreateX's `_parseSalt`). Operator and
    ///      flag are LEFT-shifts that position a field; the entropy shift is a
    ///      RIGHT-shift that pulls the top 11 bytes of the keccak down into
    ///      bytes 21..31 — the opposite direction, named apart so a future `<<`
    ///      cannot silently smash the salt.
    uint256 internal constant _SALT_OPERATOR_SHIFT = 96; // << places bytes 0..19
    uint256 internal constant _SALT_FLAG_SHIFT = 88; // << places byte 20
    uint256 internal constant _KECCAK_TO_ENTROPY_SHIFT = 168; // >> keccak into bytes 21..31

    /// @dev Assemble the sender-guarded raw salt, all 32 bytes accounted for:
    ///
    ///        byte  0 .. 19   operator address  → CreateX takes the MsgSender branch
    ///        byte       20   0x00              → cross-chain flag OFF
    ///        byte 21 .. 31   keccak(preimage)[0:11]
    ///
    ///      The flag term ORs in zero and is therefore a no-op at runtime; it is
    ///      spelled out so the layout is complete on the page rather than being an
    ///      unwritten gap between the other two fields. `_assertSaltLayout` is what
    ///      actually enforces it.
    function _rawSalt(address operator, bytes memory saltPreimage) internal pure returns (bytes32) {
        bytes32 salt = bytes32(uint256(uint160(operator)) << _SALT_OPERATOR_SHIFT)
            | bytes32(CROSSCHAIN_FLAG_OFF << _SALT_FLAG_SHIFT)
            | (keccak256(saltPreimage) >> _KECCAK_TO_ENTROPY_SHIFT);
        _assertSaltLayout(operator, salt);
        return salt;
    }

    /// @dev Fail closed on the two layout properties CreateX branches on. Neither
    ///      can be wrong by construction *today* — this exists so a future edit to
    ///      `_rawSalt` cannot silently move us onto a different branch, because
    ///      taking the wrong branch does NOT revert inside CreateX: it deploys
    ///      successfully, at a different address.
    ///
    ///      Runs inside `_rawSalt`, so it covers prediction as well as deployment.
    function _assertSaltLayout(address operator, bytes32 rawSalt_) internal pure {
        require(
            address(uint160(uint256(rawSalt_ >> _SALT_OPERATOR_SHIFT))) == operator,
            "salt layout: bytes 0-19 are not the operator (CreateX would take the permissionless branch)"
        );
        require(
            uint8(uint256(rawSalt_ >> _SALT_FLAG_SHIFT)) == CROSSCHAIN_FLAG_OFF,
            "salt layout: byte 20 is not 0x00 (CreateX would bind block.chainid and break chain-invariance)"
        );
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
    ///      already exists at the canonical address — the skip proves only that
    ///      SOMETHING has code there, so every caller must follow up with an
    ///      identity check (`_assertErc1967Proxy` for proxies, a view call on a
    ///      constructor-set immutable for implementations).
    ///
    ///      Requires the broadcaster to BE the operator, and that check is
    ///      load-bearing rather than cosmetic: CreateX does NOT revert for a wrong
    ///      caller. `_parseSalt` sees leading bytes matching neither `msg.sender`
    ///      nor `address(0)`, falls through to the PERMISSIONLESS branch, and
    ///      deploys SUCCESSFULLY at a different address. Verified against the real
    ///      singleton by
    ///      `test_senderGuard_strangerLandsElsewhere_canonicalUntouched`.
    function _createXDeploy(
        address operator,
        uint256 privateKey,
        bytes memory bytecode,
        bytes memory saltPreimage,
        string memory name
    ) internal returns (address deployed) {
        require(vm.addr(privateKey) == operator, string.concat(name, ": broadcaster is not DEPLOY_OPERATOR"));
        bytes32 rawSalt = _rawSalt(operator, saltPreimage);
        address expected = _predictCreateX(operator, saltPreimage);
        if (expected.code.length > 0) {
            // Informational only — every live artifact carries immutables, so the
            // runtime codehash is a function of the deploy params and cannot be
            // pinned. Callers prove identity with view calls (`_assertErc1967Proxy`
            // and the per-artifact checks in the deploy bases).
            console.log(string.concat("  - ", name, " already has code at"), expected);
            console.log("    codehash:", vm.toString(expected.codehash));
            return expected;
        }
        require(CREATEX.code.length > 0, "CreateX not deployed on this chain");
        // Pin our CREATE3 math (proxy initcode + child at nonce 1) against
        // CreateX's own, before spending gas: hand CreateX the guarded salt WE
        // computed and require it predicts the same address. This does NOT
        // exercise CreateX's `_guard` — `computeCreate3Address` takes an
        // already-guarded salt. `_guard` is pinned separately, by `deployed ==
        // expected` after the broadcast and by
        // `test_senderGuard_strangerLandsElsewhere_canonicalUntouched`.
        require(
            ICreateX(CREATEX).computeCreate3Address(_guardedSalt(operator, rawSalt)) == expected,
            string.concat(name, ": local prediction disagrees with CreateX")
        );
        console.log(string.concat("  - ", name, " deploying to"), expected);
        vm.startBroadcast(privateKey);
        deployed = ICreateX(CREATEX).deployCreate3(rawSalt, bytecode);
        vm.stopBroadcast();
        require(deployed == expected, string.concat(name, ": CREATE3 address mismatch"));
        console.log(string.concat("  - ", name, " deployed at"), deployed);
    }

    /// @dev Read one word from a getter on `target` via staticcall. Used for the
    ///      identity checks: a raw `Typed(target).getter()` on foreign code fails
    ///      with an opaque decode revert, whereas this names the artifact whose
    ///      canonical address is not answering.
    function _identityWord(address target, bytes4 selector, string memory name)
        internal
        view
        returns (bytes32)
    {
        (bool ok, bytes memory ret) = target.staticcall(abi.encodeWithSelector(selector));
        require(
            ok && ret.length == 32,
            string.concat(name, ": code at the canonical address does not answer the identity call")
        );
        return abi.decode(ret, (bytes32));
    }

    function _readUint(address target, bytes4 selector, string memory name)
        internal
        view
        returns (uint256)
    {
        return uint256(_identityWord(target, selector, name));
    }

    function _readAddress(address target, bytes4 selector, string memory name)
        internal
        view
        returns (address)
    {
        return address(uint160(uint256(_identityWord(target, selector, name))));
    }

    /// @dev The implementation an ERC-1967 proxy currently delegates to. Zero when
    ///      the address holds no proxy — including when it holds no code at all.
    function _erc1967Impl(address proxy) internal view returns (address) {
        return address(uint160(uint256(vm.load(proxy, ERC1967_IMPL_SLOT))));
    }

    /// @dev Identity check for a canonical ERC-1967 proxy address, run on BOTH the
    ///      fresh-deploy and the idempotent-skip path — the skip alone proves only
    ///      that *something* has code there.
    ///
    ///      Deliberately not `slot == impl`: a proxy that pre-existed this run may
    ///      legitimately point at a NEWER implementation (UUPS upgrade), and both
    ///      the factory and the paymaster are upgradeable. So require a non-zero
    ///      implementation slot — which foreign, non-proxy code will not have — and
    ///      surface a divergent target loudly instead of failing on it.
    function _assertErc1967Proxy(address proxy, address impl, string memory name) internal view {
        address current = _erc1967Impl(proxy);
        require(
            current != address(0),
            string.concat(name, ": code at the canonical proxy address is not an ERC-1967 proxy")
        );
        if (current != impl) {
            console.log(
                string.concat("  - ", name, " points at a different impl (upgraded since this build):"),
                current
            );
        }
    }
}
