// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {QuipPaymasterTest} from "../QuipPaymaster.t.sol";
import {QuipPaymaster} from "../../../../contracts/deprecated/QuipPaymaster.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.2.0/contracts/WOTSPlus.sol";

/// @dev Minimal in-memory EntryPoint mirroring the subset the paymaster touches
///      during validation. Shared with the depositStakeLifecycle file but
///      redefined here to keep scenario files self-contained.
contract MockEntryPointForUpgrade {
    mapping(address => uint256) public deposits;

    function depositTo(address account) external payable {
        deposits[account] += msg.value;
    }

    function balanceOf(address account) external view returns (uint256) {
        return deposits[account];
    }

    receive() external payable {}
}

/// @title QuipPaymaster UUPS Upgrade Scenario
/// @dev Simulates the full UUPS upgrade lifecycle: deploy → register a verifier
///      → rotate it once via validate → upgrade to a fresh implementation →
///      confirm state (owner, verifier map, deposit balance) survives → rotate
///      again post-upgrade to prove validation still works.
contract QuipPaymaster_paymasterUpgrade is QuipPaymasterTest {
    function setUp() public override {
        super.setUp();
        // Etch a mock EntryPoint so getDeposit reflects what was deposited.
        MockEntryPointForUpgrade mock = new MockEntryPointForUpgrade();
        vm.etch(ENTRY_POINT, address(mock).code);
        vm.deal(address(paymaster), 0);
    }

    function test_simulation_paymasterUpgrade() public {
        // ── Step 1: Fund + rotate the verifier once under the initial impl ──
        vm.deal(ADMIN, 5 ether);
        vm.prank(ADMIN);
        paymaster.deposit{value: 3 ether}();
        assertEq(paymaster.getDeposit(), 3 ether);

        (WOTSPlus.WinternitzAddress memory afterFirst, bytes32 afterFirstPriv) = _generateKeyPair("pmu-after-first");
        {
            bytes memory data1 = _buildPaymasterAndData(
                WALLET,
                0,
                "",
                uint48(block.timestamp + 1 hours),
                uint48(0),
                verifierPubkey,
                verifierPrivateKey,
                afterFirst
            );
            vm.prank(ENTRY_POINT);
            paymaster.validatePaymasterUserOp(_mockUserOp(data1), bytes32(0), 0);
        }
        assertEq(paymaster.getPqVerifier(WALLET).publicSeed, afterFirst.publicSeed);

        // Snapshot observable pre-upgrade state.
        address ownerPre = paymaster.owner();
        WOTSPlus.WinternitzAddress memory verifierPre = paymaster.getPqVerifier(WALLET);
        uint256 depositPre = paymaster.getDeposit();

        // ── Step 2: Deploy a fresh implementation and upgrade ─────────
        QuipPaymaster newImpl = new QuipPaymaster();
        vm.prank(ADMIN);
        paymaster.upgradeToAndCall(address(newImpl), "");

        // ── Step 3: State survived the upgrade ────────────────────────
        assertEq(paymaster.owner(), ownerPre);
        assertEq(paymaster.getPqVerifier(WALLET).publicSeed, verifierPre.publicSeed);
        assertEq(paymaster.getPqVerifier(WALLET).publicKeyHash, verifierPre.publicKeyHash);
        assertEq(paymaster.getDeposit(), depositPre);

        // ── Step 4: Validation continues working post-upgrade ─────────
        //   Rotate once more using the current verifier (= afterFirst).
        (WOTSPlus.WinternitzAddress memory afterUpgrade,) = _generateKeyPair("pmu-after-upgrade");
        bytes memory data2 = _buildPaymasterAndData(
            WALLET, 0, "", uint48(block.timestamp + 1 hours), uint48(0), afterFirst, afterFirstPriv, afterUpgrade
        );
        vm.prank(ENTRY_POINT);
        (, uint256 validationData) = paymaster.validatePaymasterUserOp(_mockUserOp(data2), bytes32(0), 0);

        // Authorizer == 0 signals validation success.
        assertEq(uint160(validationData), 0);
        assertEq(paymaster.getPqVerifier(WALLET).publicSeed, afterUpgrade.publicSeed);
    }

    /// @dev Non-owner cannot upgrade even if they've just come off a successful
    ///      validation flow — the UUPS auth gate is distinct from the
    ///      validation path.
    function test_simulation_paymasterUpgrade_nonOwnerBlocked() public {
        QuipPaymaster newImpl = new QuipPaymaster();

        // A non-owner attempting to upgrade must revert, even if they've been
        // sending valid UserOps.
        vm.prank(ALICE);
        vm.expectRevert(); // Solady Unauthorized
        paymaster.upgradeToAndCall(address(newImpl), "");

        // Owner, verifier, and deposit are all intact.
        assertEq(paymaster.owner(), ADMIN);
        assertEq(paymaster.getPqVerifier(WALLET).publicSeed, verifierPubkey.publicSeed);
    }
}
