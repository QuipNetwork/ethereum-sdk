// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {IEntryPoint, IEntryPointStake, PackedUserOperation} from "@openzeppelin-contracts-5.6.0-rc.1/interfaces/draft-IERC4337.sol";
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
/// @dev Forks Base Sepolia for the real ERC-4337 v0.7 EntryPoint, overrides `block.chainid` to 31337
///      (so the live `getUserOpHash` and both SHRINCS domain separators reproduce the values the
///      vectors were signed under), and `vm.etch`es the wallet + paymaster harnesses at their fixed
///      vector addresses. The paymaster is funded + staked so it can sponsor; the wallet holds ETH so
///      `execute` can transfer. Each assembled op is cross-checked against the live `getUserOpHash`.
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
        super.setUp(); // reads the vectors file
        vm.createSelectFork(vm.envString(BASE_SEPOLIA_RPC_ENV));
        // Pin chainid to the value the vectors bind (the live EntryPoint reads block.chainid).
        vm.chainId(CHAIN_ID);

        // ── Place the wallet at its fixed vector address ──
        factory = new MockShrincsFactory(); // executeFee defaults to 0
        ShrincsWalletHarness walletImpl = new ShrincsWalletHarness(
            payable(address(factory))
        );
        vm.etch(WALLET, address(walletImpl).code);
        wallet = ShrincsWalletHarness(payable(WALLET));
        wallet.harness_install(
            WALLET_OWNER,
            _bytes32(".walletKey.publicKeyCommitment"),
            uint8(vm.parseJsonUint(vectors, ".walletKey.parameterSetId")),
            _bytes32(".walletKey.publicKeyCommitment"), // erc1271 unused in e2e; reuse main
            uint8(vm.parseJsonUint(vectors, ".walletKey.parameterSetId")),
            MAX_SIG
        );

        // ── Place the paymaster at its fixed vector address ──
        ShrincsPaymasterHarness pmImpl = new ShrincsPaymasterHarness();
        vm.etch(PAYMASTER, address(pmImpl).code);
        paymaster = ShrincsPaymasterHarness(payable(PAYMASTER));
        paymaster.harness_setOwner(ADMIN);
        paymaster.harness_install(
            _bytes32(".verifierKey.publicKeyCommitment"),
            uint8(vm.parseJsonUint(vectors, ".verifierKey.parameterSetId")),
            MAX_SIG
        );

        // ── Fund: wallet holds ETH to transfer; paymaster deposits + stakes to sponsor ──
        vm.deal(WALLET, 10 ether);
        vm.deal(address(this), 100 ether);
        paymaster.deposit{value: 20 ether}();
        // give the wallet a small EntryPoint deposit so we can assert it is NOT touched
        IEntryPointStake(ENTRY_POINT).depositTo{value: 1 ether}(WALLET);
        vm.deal(ADMIN, 10 ether);
        vm.prank(ADMIN);
        paymaster.addStake{value: 1 ether}(1 days);

        // Callee for the contract-call case, at the fixed vector address.
        MockCallTarget targetImpl = new MockCallTarget();
        vm.etch(CALL_TARGET, address(targetImpl).code);
        callTarget = MockCallTarget(payable(CALL_TARGET));
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                      HELPERS                           */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Assemble case `name` AND assert it reproduces the live EntryPoint's userOpHash (the
    ///      decisive check that the pre-generated wallet signature will validate on-chain).
    function _op(
        string memory name
    ) internal view returns (PackedUserOperation memory op) {
        op = _assembleOp(name);
        assertEq(
            IEntryPointExt(ENTRY_POINT).getUserOpHash(op),
            _vectorUserOpHash(name),
            string.concat(name, ": live getUserOpHash != vector userOpHash")
        );
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
