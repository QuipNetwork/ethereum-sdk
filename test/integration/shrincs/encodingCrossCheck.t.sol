// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {PackedUserOperation} from "@openzeppelin-contracts-5.6.0-rc.1/interfaces/draft-IERC4337.sol";
import {SHRINCS} from "@quip.network/hashsigs-solidity-0.2.0/contracts/SHRINCS.sol";
import {SPHINCSPlusC} from "@quip.network/hashsigs-solidity-0.2.0/contracts/SPHINCSPlusC.sol";
import {UXMSS} from "@quip.network/hashsigs-solidity-0.2.0/contracts/UXMSS.sol";
import {HashSuite} from "shrincs-hash/HashSuite.sol";
import {SHRINCSParams} from "shrincs-profile/SHRINCSParams.sol";
import {SHRINCS256sKeccak} from "@quip.network/hashsigs-solidity-0.2.0/contracts/SHRINCS256sKeccak.sol";
import {ShrincsWalletHarness} from "../../harness/ShrincsWalletHarness.sol";
import {ShrincsWalletCodecHarness} from "../../harness/ShrincsWalletCodecHarness.sol";
import {ShrincsPaymasterHarness} from "../../harness/ShrincsPaymasterHarness.sol";
import {MockShrincsFactory} from "../../mocks/MockShrincsFactory.sol";
import {ShrincsE2EAssembler} from "./ShrincsE2EAssembler.t.sol";

/// @dev No-fork validation that the assembler's mirrored hashes match the live contracts. The
///      assembler signs over ITS OWN reconstructions of the wallet/paymaster domain separators and
///      the paymaster binding hash; if any mirror drifts from the production formula, every e2e
///      signature would silently stop validating — this catches that immediately, with no RPC.
contract ShrincsE2E_encodingCrossCheck is ShrincsE2EAssembler {
    ShrincsWalletHarness internal wallet;
    ShrincsPaymasterHarness internal paymaster;

    function setUp() public override {
        super.setUp();
        vm.chainId(CHAIN_ID);
        MockShrincsFactory factory = new MockShrincsFactory();
        // Domain-separator mirrors only — nothing verifies here, but the ctors zero-check.
        SHRINCS256sKeccak verifier = new SHRINCS256sKeccak();
        ShrincsWalletHarness walletImpl =
            new ShrincsWalletHarness(payable(address(factory)), address(verifier));
        vm.etch(WALLET, address(walletImpl).code);
        wallet = ShrincsWalletHarness(payable(WALLET));
        ShrincsPaymasterHarness pmImpl = new ShrincsPaymasterHarness(address(verifier));
        vm.etch(PAYMASTER, address(pmImpl).code);
        paymaster = ShrincsPaymasterHarness(payable(PAYMASTER));
    }

    function test_crossCheck_walletDomainSeparator() public view {
        assertEq(
            _walletDomainSeparator(),
            wallet.exposed_shrincsDomainSeparator(),
            "wallet domain separator mirror drift"
        );
    }

    function test_crossCheck_paymasterDomainSeparator() public view {
        assertEq(
            _pmDomainSeparator(),
            paymaster.exposed_domainSeparator(),
            "paymaster domain separator mirror drift"
        );
    }

    function test_crossCheck_paymasterBindingHash() public view {
        // A representative signed op (verification only needs the byte layout, not validity).
        PackedUserOperation memory op = _sponsoredOp(RECIPIENT, 0.1 ether, "", 0, 1);
        // Rebuild the blob-less op the paymaster's binding hash is defined over.
        PackedUserOperation memory prefixOnly = op;
        bytes memory prefix = new bytes(64);
        for (uint256 i = 0; i < 64; i++) {
            prefix[i] = op.paymasterAndData[i];
        }
        prefixOnly.paymasterAndData = prefix;
        assertEq(
            _pmBindingHash(prefixOnly),
            paymaster.exposed_userOpBindingHash(op),
            "paymaster binding hash mirror drift"
        );
    }

    /// @dev The assembler hand-mirrors `Codec.erc4337PayloadHash` (ONE word — no fee: the maxFee
    ///      ceiling rides in callData under userOpHash). If the codec's digest shape ever moves
    ///      without the mirror, every e2e wallet signature silently stops validating; this pins
    ///      them together directly.
    function test_crossCheck_erc4337PayloadHashMirror() public {
        ShrincsWalletCodecHarness codec = new ShrincsWalletCodecHarness();
        bytes32 userOpHash = keccak256("cross-check-user-op");
        assertEq(
            keccak256(abi.encodePacked(userOpHash)), // the assembler's mirror formula
            codec.exposed_erc4337PayloadHash(userOpHash),
            "erc4337 payload hash mirror drift"
        );
    }

    /// @dev The assembler hand-mirrors the wallet's userOp EIP-712 co-signature target; if the
    ///      wallet's domain (name/version/typehash) ever moves without the mirror, every e2e
    ///      co-signature silently stops validating — this pins them together directly.
    function test_crossCheck_userOpEcdsaTargetMirror() public view {
        bytes32 userOpHash = keccak256("cross-check-cosig-target");
        assertEq(
            _userOpEcdsaTargetMirror(userOpHash),
            wallet.quipUserOpHashEcdsaTarget(userOpHash),
            "userOp ECDSA target mirror drift"
        );
    }

    /// @dev Pins that the signed blob's ABI shape round-trips (the fork suite verifies the
    ///      signatures themselves against the wallet harness).
    function test_crossCheck_userOpSignatureBlobDecodes() public view {
        PackedUserOperation memory op = _sponsoredOp(RECIPIENT, 0.1 ether, "", 0, 1);
        (SHRINCS.PublicKey memory pk, SHRINCS.Signature memory sig, bytes memory ecdsaSig) =
            abi.decode(op.signature, (SHRINCS.PublicKey, SHRINCS.Signature, bytes));
        assertEq(_toBytes32(pk.publicKeyCommitment), walletCommitment, "wallet pk round-trips");
        assertEq(sig.authPath.length, 1, "leaf-1 signature round-trips");
        assertEq(ecdsaSig.length, 65, "owner co-signature round-trips");
    }
}
