// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {PackedUserOperation} from "@openzeppelin-contracts-5.6.0-rc.1/interfaces/draft-IERC4337.sol";
import {ShrincsPaymasterTest} from "../ShrincsPaymaster.t.sol";

/// @dev Behavior tests for the PURE `_userOpBindingHash`. Fully testable now (no signature): it must
///      bind every committed userOp field and the `paymasterAndData[:64]` prefix, and must EXCLUDE
///      the `paymasterAndData[64:]` signature region (to break the circular dependency).
contract ShrincsPaymaster__userOpBindingHash is ShrincsPaymasterTest {
    address internal constant SENDER = address(0xA11CE);

    /// @dev A non-trivial baseline op (non-empty initCode/callData so mutations are observable).
    function _baseline() internal view returns (PackedUserOperation memory op) {
        op = _userOp(
            SENDER,
            _paymasterAndData(111, 222, _blob(_pk(), _statefulSigWithLeaf(1)))
        );
        op.nonce = 7;
        op.initCode = hex"abcd";
        op.callData = hex"deadbeef";
    }

    function _hash(
        PackedUserOperation memory op
    ) internal view returns (bytes32) {
        return paymaster.exposed_userOpBindingHash(op);
    }

    function test_bindingHash_isDeterministic() public view {
        assertEq(_hash(_baseline()), _hash(_baseline()));
    }

    function test_bindingHash_bindsSender() public view {
        PackedUserOperation memory op = _baseline();
        op.sender = address(0xBEEF);
        assertTrue(_hash(op) != _hash(_baseline()), "sender is bound");
    }

    function test_bindingHash_bindsNonce() public view {
        PackedUserOperation memory op = _baseline();
        op.nonce = 8;
        assertTrue(_hash(op) != _hash(_baseline()), "nonce is bound");
    }

    function test_bindingHash_bindsInitCode() public view {
        PackedUserOperation memory op = _baseline();
        op.initCode = hex"abce";
        assertTrue(_hash(op) != _hash(_baseline()), "initCode is bound");
    }

    function test_bindingHash_bindsCallData() public view {
        PackedUserOperation memory op = _baseline();
        op.callData = hex"deadbeff"; // differs from the baseline's 0xdeadbeef
        assertTrue(_hash(op) != _hash(_baseline()), "callData is bound");
    }

    function test_bindingHash_bindsAccountGasLimits() public view {
        PackedUserOperation memory op = _baseline();
        op.accountGasLimits = bytes32(uint256(1));
        assertTrue(
            _hash(op) != _hash(_baseline()),
            "accountGasLimits is bound"
        );
    }

    function test_bindingHash_bindsPreVerificationGas() public view {
        PackedUserOperation memory op = _baseline();
        op.preVerificationGas = 22_000;
        assertTrue(
            _hash(op) != _hash(_baseline()),
            "preVerificationGas is bound"
        );
    }

    function test_bindingHash_bindsGasFees() public view {
        PackedUserOperation memory op = _baseline();
        op.gasFees = bytes32(uint256(1));
        assertTrue(_hash(op) != _hash(_baseline()), "gasFees is bound");
    }

    function test_bindingHash_bindsPaymasterPrefix_validUntil() public view {
        PackedUserOperation memory op = _baseline();
        op.paymasterAndData = _paymasterAndData(
            999,
            222,
            _blob(_pk(), _statefulSigWithLeaf(1))
        );
        assertTrue(
            _hash(op) != _hash(_baseline()),
            "validUntil (in the bound prefix) is bound"
        );
    }

    function test_bindingHash_bindsPaymasterPrefix_validAfter() public view {
        PackedUserOperation memory op = _baseline();
        op.paymasterAndData = _paymasterAndData(
            111,
            999, // baseline validAfter is 222
            _blob(_pk(), _statefulSigWithLeaf(1))
        );
        assertTrue(
            _hash(op) != _hash(_baseline()),
            "validAfter (in the bound prefix) is bound"
        );
    }

    /// @dev The gas-limit region of the prefix — verificationGasLimit[20:36] and postOpGasLimit[36:52]
    ///      — sits inside `paymasterAndData[:64]` and must be bound. The baseline helper hardcodes
    ///      those two limits, so this hand-packs a prefix with different ones (same window + blob).
    function test_bindingHash_bindsPaymasterPrefix_gasLimits() public view {
        PackedUserOperation memory op = _baseline();
        op.paymasterAndData = abi.encodePacked(
            PAYMASTER,
            uint128(PM_VERIFICATION_GAS + 1), // perturb verificationGasLimit
            uint128(PM_POSTOP_GAS + 1), // perturb postOpGasLimit
            uint48(111),
            uint48(222),
            _blob(_pk(), _statefulSigWithLeaf(1))
        );
        assertTrue(
            _hash(op) != _hash(_baseline()),
            "paymaster gas-limit region (in the bound prefix) is bound"
        );
    }

    function test_bindingHash_excludesSignatureRegion() public view {
        // Same prefix [:64], different signature blob [64:] — the hash must NOT change.
        PackedUserOperation memory op = _baseline();
        op.paymasterAndData = _paymasterAndData(
            111,
            222,
            _blob(_pk(), _statefulSigWithLeaf(2))
        );
        assertEq(
            _hash(op),
            _hash(_baseline()),
            "signature region is excluded from the binding hash"
        );
    }

    /* ─────────────────────────────── FUZZ ─────────────────────────────── */

    /// @dev Determinism over arbitrary bound fields: the hash is a pure function of the userOp, so the
    ///      same field set always yields the same digest.
    function testFuzz_bindingHash_isDeterministic(
        address sender,
        uint256 nonce,
        bytes32 accountGasLimits,
        uint256 preVerificationGas,
        bytes32 gasFees
    ) public view {
        PackedUserOperation memory op = _baseline();
        op.sender = sender;
        op.nonce = nonce;
        op.accountGasLimits = accountGasLimits;
        op.preVerificationGas = preVerificationGas;
        op.gasFees = gasFees;
        assertEq(_hash(op), _hash(op));
    }

    /// @dev Injectivity over the scalar fields: changing any single bound field changes the digest.
    ///      Distinct (sender, nonce, accountGasLimits, preVerificationGas, gasFees) tuples must not
    ///      collide (a degenerate construction that dropped a field would be caught here).
    function testFuzz_bindingHash_distinctFieldsDistinctHash(
        address sender,
        uint256 nonce,
        bytes32 accountGasLimits,
        uint256 preVerificationGas,
        bytes32 gasFees
    ) public view {
        PackedUserOperation memory base = _baseline();
        // Assume at least one field actually differs from the baseline.
        vm.assume(
            sender != base.sender ||
                nonce != base.nonce ||
                accountGasLimits != base.accountGasLimits ||
                preVerificationGas != base.preVerificationGas ||
                gasFees != base.gasFees
        );
        PackedUserOperation memory op = _baseline();
        op.sender = sender;
        op.nonce = nonce;
        op.accountGasLimits = accountGasLimits;
        op.preVerificationGas = preVerificationGas;
        op.gasFees = gasFees;
        assertTrue(
            _hash(op) != _hash(base),
            "distinct bound fields produce a distinct hash"
        );
    }
}
