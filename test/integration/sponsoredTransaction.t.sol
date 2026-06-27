// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {IQuipWallet} from "../../contracts/interfaces/IQuipWallet.sol";

import {IntegrationBase, IEntryPoint, IEntryPointExt, IEntryPointStake, PackedUserOperation} from "./IntegrationBase.t.sol";
import {EfficientHashLib} from "solady-0.1.26/src/utils/EfficientHashLib.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.1.0/contracts/WOTSPlus.sol";
import {WOTSPlusCodec as Codec} from "../../contracts/WOTSPlusCodec.sol";

/// @title Sponsored Transaction Integration Test
/// @dev Fork test against the real EntryPoint v0.7 on Base Sepolia.
///      Full end-to-end flow: the QuipPaymaster sponsors a QuipWallet UserOp.
///      The EntryPoint orchestrates validatePaymasterUserOp → validateUserOp →
///      execution → postOp. Proves sponsorship via deposit accounting and event.
contract Integration_sponsoredTransaction is IntegrationBase {
    /// @dev Domain tag for paymaster approval digests (must match QuipPaymaster).
    bytes32 private constant _PAYMASTER_APPROVE_TAG =
        keccak256("quip.digest.paymasterApprove");

    /// @dev Paymaster's WOTS+ verifier key for the wallet.
    WOTSPlus.WinternitzAddress public verifierPubkey;
    bytes32 public verifierPrivateKey;

    function setUp() public override {
        super.setUp();
        _deployWalletStack();
        _deployPaymaster();

        // ── Step 1: Register the wallet with the paymaster ──────────
        // The paymaster owner (ADMIN) registers a per-wallet WOTS+ verifier key.
        // This is the whitelist: only wallets with a registered verifier get sponsored.
        (verifierPubkey, verifierPrivateKey) = _generateKeyPair(
            "verifier-seed-0"
        );
        vm.prank(ADMIN);
        paymaster.setPqVerifier(address(wallet), verifierPubkey);

        // ── Step 2: Fund the paymaster's EntryPoint deposit ─────────
        // This deposit is what pays for gas. The wallet does NOT need a deposit.
        vm.deal(address(paymaster), 10 ether);
        paymaster.deposit{value: 10 ether}();

        // ── Step 3: Stake the paymaster (required by EntryPoint for paymasters) ──
        vm.prank(ADMIN);
        paymaster.addStake{value: 1 ether}(60);
    }

    // ── Paymaster data helpers ──────────────────────────────────────

    /// @dev Build the `paymasterAndData` field for a sponsored UserOp.
    ///      Layout: [0:20) paymaster address
    ///              [20:36) paymasterVerificationGasLimit (uint128)
    ///              [36:52) paymasterPostOpGasLimit (uint128)
    ///              --- paymaster custom data starts at offset 52 ---
    ///              [52:58)   validUntil (uint48)
    ///              [58:64)   validAfter (uint48)
    ///              [64:128)  nextVerifier (publicSeed + publicKeyHash)
    ///              [128:2272) WOTS+ signature (67 × 32 bytes)
    function _buildPaymasterAndData(
        address sender,
        uint256 nonce,
        bytes memory callData_,
        WOTSPlus.WinternitzAddress memory currentVerifier,
        bytes32 currentVerifierPriv,
        WOTSPlus.WinternitzAddress memory nextVerifier,
        uint48 validUntil,
        uint48 validAfter
    ) internal view returns (bytes memory) {
        // Build the domain-tagged digest from UserOp fields (not userOpHash).
        bytes32 opCommitment = EfficientHashLib.hash(
            bytes32(uint256(uint160(sender))),
            bytes32(nonce),
            EfficientHashLib.hash(callData_)
        );

        bytes32 digest = EfficientHashLib.hash(
            _PAYMASTER_APPROVE_TAG,
            bytes32(block.chainid),
            bytes32(uint256(uint160(address(paymaster)))),
            currentVerifier.publicSeed,
            currentVerifier.publicKeyHash,
            nextVerifier.publicSeed,
            nextVerifier.publicKeyHash,
            opCommitment
        );

        WOTSPlus.WinternitzElements memory sig = _sign(
            currentVerifierPriv,
            digest
        );

        return
            abi.encodePacked(
                address(paymaster),
                uint128(5_000_000), // paymasterVerificationGasLimit
                uint128(50_000), // paymasterPostOpGasLimit
                validUntil,
                validAfter,
                nextVerifier.publicSeed,
                nextVerifier.publicKeyHash,
                sig.elements
            );
    }

    /// @dev Default-window wrapper: signs with the active verifier, validUntil
    ///      = now + 1h, validAfter = 0.
    function _buildPaymasterAndData(
        address sender,
        uint256 nonce,
        bytes memory callData_,
        WOTSPlus.WinternitzAddress memory nextVerifier
    ) internal view returns (bytes memory) {
        return
            _buildPaymasterAndData(
                sender,
                nonce,
                callData_,
                verifierPubkey,
                verifierPrivateKey,
                nextVerifier,
                uint48(block.timestamp + 1 hours),
                uint48(0)
            );
    }

    /// @dev Build a sponsored UserOp: wallet signature + paymaster data.
    ///      The paymaster digest is built from UserOp fields (not userOpHash),
    ///      so paymasterAndData can be computed before the wallet signature.
    function _buildSponsoredUserOp(
        address target,
        uint256 value,
        bytes memory data,
        WOTSPlus.WinternitzAddress memory currentWalletPq,
        bytes32 walletPrivKey,
        WOTSPlus.WinternitzAddress memory nextWalletPq,
        WOTSPlus.WinternitzAddress memory nextVerifier
    ) internal returns (PackedUserOperation memory userOp) {
        bytes memory callData_ = abi.encodeWithSelector(
            bytes4(keccak256("execute(address,uint256,bytes)")),
            target,
            value,
            data
        );

        // Build the base UserOp
        userOp = PackedUserOperation({
            sender: address(wallet),
            nonce: 0,
            initCode: "",
            callData: callData_,
            accountGasLimits: bytes32(
                (uint256(5_000_000) << 128) | uint256(500_000)
            ),
            preVerificationGas: 100_000,
            gasFees: bytes32((uint256(1 gwei) << 128) | uint256(10 gwei)),
            paymasterAndData: "",
            signature: ""
        });

        // Paymaster signature is independent of paymasterAndData — no circular dependency.
        userOp.paymasterAndData = _buildPaymasterAndData(
            address(wallet),
            0,
            callData_,
            nextVerifier
        );

        // Compute userOpHash (now stable) and sign the wallet's portion.
        bytes32 userOpHash = IEntryPointExt(ENTRY_POINT).getUserOpHash(userOp);
        uint256 fee = wallet.getExecuteFee();
        bytes32 walletDigest = Codec.erc4337ExecuteDigest(
            address(wallet),
            block.chainid,
            currentWalletPq.publicSeed,
            currentWalletPq.publicKeyHash,
            nextWalletPq.publicSeed,
            nextWalletPq.publicKeyHash,
            userOpHash,
            fee
        );
        WOTSPlus.WinternitzElements memory walletSig = _sign(
            walletPrivKey,
            walletDigest
        );
        userOp.signature = Codec.encodeUserOpSignature(
            alicePubkey,
            nextWalletPq,
            walletSig
        );
    }

    // ── Tests ───────────────────────────────────────────────────────

    /// @dev Full sponsored transaction: paymaster pays gas, wallet executes ETH transfer.
    ///      Proves sponsorship via deposit accounting.
    function test_integration_sponsoredTransaction_paymasterPaysGas() public {
        (WOTSPlus.WinternitzAddress memory nextWalletPq, ) = _generateKeyPair(
            "sponsored-next-wallet-key"
        );
        (WOTSPlus.WinternitzAddress memory nextVerifier, ) = _generateKeyPair(
            "sponsored-next-verifier"
        );

        uint256 transferAmount = 0.1 ether;

        PackedUserOperation memory userOp = _buildSponsoredUserOp(
            BOB,
            transferAmount,
            "",
            alicePubkey,
            alicePrivateKey,
            nextWalletPq,
            nextVerifier
        );

        // ── Record balances BEFORE ──
        // Wallet's EntryPoint deposit (funded in _deployWalletStack)
        uint256 walletDepositBefore = IEntryPointStake(ENTRY_POINT).balanceOf(
            address(wallet)
        );

        // Paymaster's deposit is what will pay for gas
        uint256 paymasterDepositBefore = IEntryPointStake(ENTRY_POINT)
            .balanceOf(address(paymaster));
        assertTrue(paymasterDepositBefore > 0, "paymaster must have deposit");

        uint256 walletBalBefore = address(wallet).balance;
        uint256 bobBalBefore = BOB.balance;

        // ── Submit via handleOps ──
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;
        IEntryPoint(ENTRY_POINT).handleOps(ops, BENEFICIARY);

        // ── PROVE SPONSORSHIP ──

        // 1. Wallet's EntryPoint deposit is unchanged — it did NOT pay gas
        assertEq(
            IEntryPointStake(ENTRY_POINT).balanceOf(address(wallet)),
            walletDepositBefore,
            "wallet deposit must not change (paymaster paid)"
        );

        // 2. Paymaster's deposit decreased — it DID pay gas
        assertLt(
            IEntryPointStake(ENTRY_POINT).balanceOf(address(paymaster)),
            paymasterDepositBefore,
            "paymaster deposit must decrease (it paid gas)"
        );

        // 3. Wallet balance only decreased by transfer amount (+ protocol fee), NOT gas
        uint256 fee = wallet.getExecuteFee();
        assertEq(
            address(wallet).balance,
            walletBalBefore - transferAmount - fee,
            "wallet balance: only transfer + protocol fee, no gas"
        );

        // 4. BOB received the transfer
        assertEq(BOB.balance, bobBalBefore + transferAmount);

        // 5. Wallet PQ key rotated
        assertTrue(wallet.isKey(Codec.KeyType.Transaction, nextWalletPq));

        // 6. Paymaster verifier key rotated
        WOTSPlus.WinternitzAddress memory storedVerifier = paymaster
            .getPqVerifier(address(wallet));
        assertEq(storedVerifier.publicSeed, nextVerifier.publicSeed);
        assertEq(storedVerifier.publicKeyHash, nextVerifier.publicKeyHash);
    }

    /// @dev Tamper with the paymaster WOTS+ signature, then RE-SIGN the wallet
    ///      portion. `userOpHash` is derived from the full UserOp (including
    ///      `paymasterAndData`), so tampering without re-signing would break
    ///      the wallet sig first and return AA24 instead of AA34. Re-signing
    ///      the wallet portion against the tampered userOpHash isolates the
    ///      paymaster path. Expected result: `AA34 signature error`.
    function test_integration_sponsored_revertsWhen_paymasterSigTampered()
        public
    {
        (WOTSPlus.WinternitzAddress memory nextWalletPq, ) = _generateKeyPair(
            "badsig-next-wallet"
        );
        (WOTSPlus.WinternitzAddress memory nextVerifier, ) = _generateKeyPair(
            "badsig-next-verifier"
        );

        PackedUserOperation memory userOp = _buildSponsoredUserOp(
            BOB,
            0.01 ether,
            "",
            alicePubkey,
            alicePrivateKey,
            nextWalletPq,
            nextVerifier
        );

        // Corrupt a byte inside the paymaster's WOTS+ sig region. Layout:
        // [0:20)   paymaster address
        // [20:36)  verificationGasLimit
        // [36:52)  postOpGasLimit
        // [52:58)  validUntil
        // [58:64)  validAfter
        // [64:128) nextVerifier
        // [128:2272) WOTS+ sig  ← corrupt here
        bytes memory pmd = userOp.paymasterAndData;
        pmd[200] ^= bytes1(0xFF);
        userOp.paymasterAndData = pmd;

        // Re-sign wallet portion against the new userOpHash so the account
        // path validates and the paymaster path is the one that fails.
        bytes32 newUserOpHash = IEntryPointExt(ENTRY_POINT).getUserOpHash(
            userOp
        );
        bytes32 walletDigest = Codec.erc4337ExecuteDigest(
            address(wallet),
            block.chainid,
            alicePubkey.publicSeed,
            alicePubkey.publicKeyHash,
            nextWalletPq.publicSeed,
            nextWalletPq.publicKeyHash,
            newUserOpHash,
            wallet.getExecuteFee()
        );
        userOp.signature = Codec.encodeUserOpSignature(
            alicePubkey,
            nextWalletPq,
            _sign(alicePrivateKey, walletDigest)
        );

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;
        vm.expectRevert(
            abi.encodeWithSignature(
                "FailedOp(uint256,string)",
                uint256(0),
                "AA34 signature error"
            )
        );
        IEntryPoint(ENTRY_POINT).handleOps(ops, BENEFICIARY);
    }

    /// @dev `validAfter` in the future must cause the EntryPoint to reject the
    ///      op with `AA32 paymaster expired or not due` (time-range half of
    ///      validationData is packed correctly).
    function test_integration_sponsored_revertsWhen_validAfterInFuture() public {
        (WOTSPlus.WinternitzAddress memory nextWalletPq, ) = _generateKeyPair(
            "future-wallet-key"
        );
        (WOTSPlus.WinternitzAddress memory nextVerifier, ) = _generateKeyPair(
            "future-next-verifier"
        );

        bytes memory callData_ = abi.encodeWithSelector(
            bytes4(keccak256("execute(address,uint256,bytes)")),
            BOB,
            uint256(0.01 ether),
            bytes("")
        );

        PackedUserOperation memory userOp = PackedUserOperation({
            sender: address(wallet),
            nonce: 0,
            initCode: "",
            callData: callData_,
            accountGasLimits: bytes32(
                (uint256(5_000_000) << 128) | uint256(500_000)
            ),
            preVerificationGas: 100_000,
            gasFees: bytes32((uint256(1 gwei) << 128) | uint256(10 gwei)),
            paymasterAndData: _buildPaymasterAndData(
                address(wallet),
                0,
                callData_,
                verifierPubkey,
                verifierPrivateKey,
                nextVerifier,
                uint48(block.timestamp + 1 days), // validUntil > validAfter
                uint48(block.timestamp + 1 hours) // validAfter in future
            ),
            signature: ""
        });

        bytes32 userOpHash = IEntryPointExt(ENTRY_POINT).getUserOpHash(userOp);
        bytes32 walletDigest = Codec.erc4337ExecuteDigest(
            address(wallet),
            block.chainid,
            alicePubkey.publicSeed,
            alicePubkey.publicKeyHash,
            nextWalletPq.publicSeed,
            nextWalletPq.publicKeyHash,
            userOpHash,
            wallet.getExecuteFee()
        );
        userOp.signature = Codec.encodeUserOpSignature(
            alicePubkey,
            nextWalletPq,
            _sign(alicePrivateKey, walletDigest)
        );

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;
        vm.expectRevert(
            abi.encodeWithSignature(
                "FailedOp(uint256,string)",
                uint256(0),
                "AA32 paymaster expired or not due"
            )
        );
        IEntryPoint(ENTRY_POINT).handleOps(ops, BENEFICIARY);
    }

    /// @dev `validUntil` already elapsed must also cause EntryPoint to reject
    ///      with `AA32 paymaster expired or not due`.
    function test_integration_sponsored_revertsWhen_validUntilExpired() public {
        // Skip forward so `validUntil = block.timestamp - 1` is strictly past.
        vm.warp(block.timestamp + 2 hours);

        (WOTSPlus.WinternitzAddress memory nextWalletPq, ) = _generateKeyPair(
            "expired-wallet-key"
        );
        (WOTSPlus.WinternitzAddress memory nextVerifier, ) = _generateKeyPair(
            "expired-next-verifier"
        );

        bytes memory callData_ = abi.encodeWithSelector(
            bytes4(keccak256("execute(address,uint256,bytes)")),
            BOB,
            uint256(0.01 ether),
            bytes("")
        );

        PackedUserOperation memory userOp = PackedUserOperation({
            sender: address(wallet),
            nonce: 0,
            initCode: "",
            callData: callData_,
            accountGasLimits: bytes32(
                (uint256(5_000_000) << 128) | uint256(500_000)
            ),
            preVerificationGas: 100_000,
            gasFees: bytes32((uint256(1 gwei) << 128) | uint256(10 gwei)),
            paymasterAndData: _buildPaymasterAndData(
                address(wallet),
                0,
                callData_,
                verifierPubkey,
                verifierPrivateKey,
                nextVerifier,
                uint48(block.timestamp - 1), // validUntil in the past
                uint48(0)
            ),
            signature: ""
        });

        bytes32 userOpHash = IEntryPointExt(ENTRY_POINT).getUserOpHash(userOp);
        bytes32 walletDigest = Codec.erc4337ExecuteDigest(
            address(wallet),
            block.chainid,
            alicePubkey.publicSeed,
            alicePubkey.publicKeyHash,
            nextWalletPq.publicSeed,
            nextWalletPq.publicKeyHash,
            userOpHash,
            wallet.getExecuteFee()
        );
        userOp.signature = Codec.encodeUserOpSignature(
            alicePubkey,
            nextWalletPq,
            _sign(alicePrivateKey, walletDigest)
        );

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;
        vm.expectRevert(
            abi.encodeWithSignature(
                "FailedOp(uint256,string)",
                uint256(0),
                "AA32 paymaster expired or not due"
            )
        );
        IEntryPoint(ENTRY_POINT).handleOps(ops, BENEFICIARY);
    }

    /// @dev Paymaster whitelist enforcement: a wallet with no registered
    ///      verifier cannot be sponsored. `_verifyAndRotate` returns false at
    ///      the zero-verifier guard → validationData=1 → AA34.
    function test_integration_sponsored_revertsWhen_walletNotWhitelisted()
        public
    {
        // Deploy a second wallet (BOB's). The paymaster has no verifier
        // registered for it, so sponsorship must be rejected.
        (
            WOTSPlus.WinternitzAddress memory bobPubkey,
            bytes32 bobPriv
        ) = _generateKeyPair("bob-vault");
        WOTSPlus.WinternitzAddress[]
            memory bobRecovery = _generateRecoveryKeys(bobPriv, 10);
        bytes memory bobInit = _encodeInitPayload(bobPubkey, bobRecovery);

        vm.deal(BOB, 2 ether);
        vm.prank(BOB);
        address bobWalletAddr = factory.deployLatestWalletProxy{value: 1 ether}(
            keccak256("bob-vault"),
            payable(BOB),
            bobInit
        );

        (WOTSPlus.WinternitzAddress memory nextBobPq, ) = _generateKeyPair(
            "bob-next-key"
        );
        (WOTSPlus.WinternitzAddress memory nextVerifier, ) = _generateKeyPair(
            "bob-next-verifier"
        );

        bytes memory callData_ = abi.encodeWithSelector(
            bytes4(keccak256("execute(address,uint256,bytes)")),
            ALICE,
            uint256(0.01 ether),
            bytes("")
        );

        // BOB's paymasterAndData signed by ALICE's verifier key — the check
        // fails upstream of signature verification because BOB's wallet has
        // no registered verifier. (The sig here is well-formed so we are
        // specifically testing the whitelist guard.)
        bytes memory pmd = _buildPaymasterAndData(
            bobWalletAddr,
            0,
            callData_,
            verifierPubkey,
            verifierPrivateKey,
            nextVerifier,
            uint48(block.timestamp + 1 hours),
            uint48(0)
        );

        PackedUserOperation memory userOp = PackedUserOperation({
            sender: bobWalletAddr,
            nonce: 0,
            initCode: "",
            callData: callData_,
            accountGasLimits: bytes32(
                (uint256(5_000_000) << 128) | uint256(500_000)
            ),
            preVerificationGas: 100_000,
            gasFees: bytes32((uint256(1 gwei) << 128) | uint256(10 gwei)),
            paymasterAndData: pmd,
            signature: ""
        });

        bytes32 userOpHash = IEntryPointExt(ENTRY_POINT).getUserOpHash(userOp);
        bytes32 walletDigest = Codec.erc4337ExecuteDigest(
            bobWalletAddr,
            block.chainid,
            bobPubkey.publicSeed,
            bobPubkey.publicKeyHash,
            nextBobPq.publicSeed,
            nextBobPq.publicKeyHash,
            userOpHash,
            0
        );
        userOp.signature = Codec.encodeUserOpSignature(
            bobPubkey,
            nextBobPq,
            _sign(bobPriv, walletDigest)
        );

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;
        vm.expectRevert(
            abi.encodeWithSignature(
                "FailedOp(uint256,string)",
                uint256(0),
                "AA34 signature error"
            )
        );
        IEntryPoint(ENTRY_POINT).handleOps(ops, BENEFICIARY);
    }

    /// @dev Sponsored transaction with zero wallet deposit — proves wallet
    ///      literally cannot self-pay; sponsorship is the only path.
    function test_integration_sponsoredTransaction_walletHasNoDeposit() public {
        // Drain the wallet's EntryPoint deposit so it's provably zero.
        // Use the EntryPoint's withdrawTo directly via prank — this is test
        // setup, not the behavior under test.
        uint256 existingDeposit = IEntryPointStake(ENTRY_POINT).balanceOf(
            address(wallet)
        );
        if (existingDeposit > 0) {
            vm.prank(address(wallet));
            IEntryPointStake(ENTRY_POINT).withdrawTo(
                payable(ALICE),
                existingDeposit
            );
        }

        // Confirm wallet has zero deposit
        assertEq(
            IEntryPointStake(ENTRY_POINT).balanceOf(address(wallet)),
            0,
            "wallet must have zero EntryPoint deposit"
        );

        (WOTSPlus.WinternitzAddress memory nextWalletPq, ) = _generateKeyPair(
            "zero-deposit-next-key"
        );
        (WOTSPlus.WinternitzAddress memory nextVerifier, ) = _generateKeyPair(
            "zero-deposit-next-verifier"
        );

        PackedUserOperation memory userOp = _buildSponsoredUserOp(
            BOB,
            0.01 ether,
            "",
            alicePubkey,
            alicePrivateKey,
            nextWalletPq,
            nextVerifier
        );

        uint256 bobBalBefore = BOB.balance;

        // This would revert without the paymaster — wallet has no deposit
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;
        IEntryPoint(ENTRY_POINT).handleOps(ops, BENEFICIARY);

        assertEq(BOB.balance, bobBalBefore + 0.01 ether);
    }
}
