// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {PackedUserOperation} from "@openzeppelin-contracts-5.6.0-rc.1/interfaces/draft-IERC4337.sol";
import {ShrincsTypes} from "@quip.network/hashsigs-solidity-0.1.0/contracts/ShrincsTypes.sol";
import {ShrincsWalletHarness} from "../../harness/ShrincsWalletHarness.sol";
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
        ShrincsWalletHarness walletImpl = new ShrincsWalletHarness(payable(address(factory)));
        vm.etch(WALLET, address(walletImpl).code);
        wallet = ShrincsWalletHarness(payable(WALLET));
        ShrincsPaymasterHarness pmImpl = new ShrincsPaymasterHarness();
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

    /// @dev The mirrored erc4337 payload hash construction (hash(userOpHash, fee)) must match the
    ///      codec's — verified indirectly by decoding the signed blob and re-verifying against the
    ///      wallet harness in the fork suite; here we pin the blob's ABI shape round-trips.
    function test_crossCheck_userOpSignatureBlobDecodes() public view {
        PackedUserOperation memory op = _sponsoredOp(RECIPIENT, 0.1 ether, "", 0, 1);
        (ShrincsTypes.PublicKey memory pk, ShrincsTypes.StatefulSignature memory sig) =
            abi.decode(op.signature, (ShrincsTypes.PublicKey, ShrincsTypes.StatefulSignature));
        assertEq(_toBytes32(pk.publicKeyCommitment), walletCommitment, "wallet pk round-trips");
        assertEq(sig.authPath.length, 1, "leaf-1 signature round-trips");
    }
}
