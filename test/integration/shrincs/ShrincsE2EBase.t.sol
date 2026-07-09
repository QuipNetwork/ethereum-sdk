// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {IEntryPoint, IEntryPointStake, PackedUserOperation} from "@openzeppelin-contracts-5.6.0-rc.1/interfaces/draft-IERC4337.sol";
import {ShrincsTypes} from "@quip.network/hashsigs-solidity-0.1.0/contracts/ShrincsTypes.sol";
import {ShrincsWalletHarness} from "../../harness/ShrincsWalletHarness.sol";
import {ShrincsPaymasterHarness} from "../../harness/ShrincsPaymasterHarness.sol";
import {MockShrincsFactory} from "../../mocks/MockShrincsFactory.sol";
import {MockCallTarget} from "./MockCallTarget.sol";
import {ShrincsE2EAssembler} from "./ShrincsE2EAssembler.t.sol";

/// @dev Minimal extension exposing `getUserOpHash` on the forked EntryPoint.
interface IEntryPointExt is IEntryPoint {
    function getUserOpHash(
        PackedUserOperation calldata userOp
    ) external view returns (bytes32);
}

/// @title ShrincsWallet + ShrincsPaymaster e2e base
/// @dev Forks Base Sepolia for the real ERC-4337 v0.7 EntryPoint, overrides `block.chainid` to
///      31337 (a stable signing domain), and `vm.etch`es the wallet + paymaster harnesses at the
///      assembler's fixed addresses, installed with the in-test generated keys. The paymaster is
///      funded + staked so it can sponsor; the wallet holds ETH so `execute` can transfer. Each
///      assembled op is cross-checked against the live `getUserOpHash` before submission.
abstract contract ShrincsE2EBase is ShrincsE2EAssembler {
    string internal constant BASE_SEPOLIA_RPC_ENV = "API_URL_BASE_SEPOLIA";

    address internal ADMIN = makeAddr("admin");
    address internal WALLET_OWNER = makeAddr("walletOwner");
    address payable internal BENEFICIARY = payable(makeAddr("beneficiary"));

    ShrincsWalletHarness internal wallet;
    ShrincsPaymasterHarness internal paymaster;
    MockShrincsFactory internal factory;
    MockCallTarget internal callTarget;

    function setUp() public virtual override {
        super.setUp(); // generates the wallet + verifier keys
        vm.createSelectFork(vm.envString(BASE_SEPOLIA_RPC_ENV));
        // Pin chainid to the assembler's signing domain (the live EntryPoint reads block.chainid).
        vm.chainId(CHAIN_ID);

        // ── Place the wallet at its fixed address ──
        factory = new MockShrincsFactory(); // executeFee defaults to 0
        ShrincsWalletHarness walletImpl = new ShrincsWalletHarness(
            payable(address(factory))
        );
        vm.etch(WALLET, address(walletImpl).code);
        wallet = ShrincsWalletHarness(payable(WALLET));
        wallet.harness_install(
            WALLET_OWNER,
            walletCommitment,
            walletCommitment, // erc1271 unused in e2e; reuse main
            MAX_SIG
        );

        // ── Place the paymaster at its fixed address ──
        ShrincsPaymasterHarness pmImpl = new ShrincsPaymasterHarness();
        vm.etch(PAYMASTER, address(pmImpl).code);
        paymaster = ShrincsPaymasterHarness(payable(PAYMASTER));
        paymaster.harness_setOwner(ADMIN);
        paymaster.harness_install(verifierCommitment, MAX_SIG);

        // ── Fund: wallet holds ETH to transfer; paymaster deposits + stakes to sponsor ──
        vm.deal(WALLET, 10 ether);
        vm.deal(address(this), 100 ether);
        paymaster.deposit{value: 20 ether}();
        // give the wallet a small EntryPoint deposit so we can assert it is NOT touched
        IEntryPointStake(ENTRY_POINT).depositTo{value: 1 ether}(WALLET);
        vm.deal(ADMIN, 10 ether);
        vm.prank(ADMIN);
        paymaster.addStake{value: 1 ether}(1 days);

        // Callee for the contract-call case, at the fixed address.
        MockCallTarget targetImpl = new MockCallTarget();
        vm.etch(CALL_TARGET, address(targetImpl).code);
        callTarget = MockCallTarget(payable(CALL_TARGET));
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                      HELPERS                           */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Asserts the op's mirrored userOpHash matches the live EntryPoint's (the decisive check
    ///      that the wallet signature computed over the mirror will validate on-chain).
    function _assertLiveHash(PackedUserOperation memory op) internal view {
        assertEq(
            IEntryPointExt(ENTRY_POINT).getUserOpHash(op),
            _computeUserOpHash(op),
            "live getUserOpHash != mirrored userOpHash"
        );
    }

    /// @dev Builds the default sponsored op AND cross-checks it against the live EntryPoint hash.
    function _checkedSponsoredOp(address target, uint256 value, bytes memory data, uint256 nonce, uint32 leaf)
        internal
        view
        returns (PackedUserOperation memory op)
    {
        op = _sponsoredOp(target, value, data, nonce, leaf);
        _assertLiveHash(op);
    }

    function _handle(PackedUserOperation memory op) internal {
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = op;
        IEntryPoint(ENTRY_POINT).handleOps(ops, BENEFICIARY);
    }

    function _handleExpectRevert(
        PackedUserOperation memory op,
        bytes memory revertData
    ) internal {
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = op;
        vm.expectRevert(revertData);
        IEntryPoint(ENTRY_POINT).handleOps(ops, BENEFICIARY);
    }

    function _failedOp(
        uint256 opIndex,
        string memory reason
    ) internal pure returns (bytes memory) {
        return
            abi.encodeWithSignature(
                "FailedOp(uint256,string)",
                opIndex,
                reason
            );
    }

    function _deposit(address who) internal view returns (uint256) {
        return IEntryPointStake(ENTRY_POINT).balanceOf(who);
    }
}
