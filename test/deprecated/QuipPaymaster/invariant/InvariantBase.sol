// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {QuipPaymasterTest} from "../QuipPaymaster.t.sol";
import {QuipPaymaster} from "../../../../contracts/deprecated/QuipPaymaster.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.2.0/contracts/WOTSPlus.sol";
import {QuipPaymasterInvariantHandler} from "./Handler.t.sol";

/// @title QuipPaymaster Invariant Test Base
/// @dev Inherits `QuipPaymasterTest`, then layers on:
///        1. Transferring paymaster ownership from ADMIN to the Handler
///           (Solady's `Ownable` is single-step, so no acceptance call).
///        2. Pre-registering verifiers for additional pool wallets so the
///           campaign starts in a fully-populated state and validation
///           fuzz selectors have real work to do from call 0.
///        3. Handing the Handler the full mirror state — wallet pool,
///           initial verifier pubkeys, initial privkeys — so it can sign
///           valid UserOps without leaking material across contract
///           boundaries.
///
///      Subclasses declare `invariant_*` functions and call
///      `targetContract(address(handler))` from their own `setUp` after
///      `super.setUp()`. The pool size is fixed at 4 — large enough that
///      pairwise cross-wallet checks have meaningful surface, small enough
///      that snapshot-and-diff in every fuzz selector stays cheap.
abstract contract QuipPaymasterInvariantBase is QuipPaymasterTest {
    QuipPaymasterInvariantHandler public handler;

    /// @dev Four wallets — pairwise invariant scans are O(N²) but at N=4
    ///      this is six comparisons per check, negligible against WOTS+
    ///      verify cost.
    uint256 internal constant WALLET_POOL_SIZE = 4;

    function setUp() public virtual override {
        super.setUp();

        handler = new QuipPaymasterInvariantHandler();

        // Compose the wallet pool. Slot 0 is the inherited WALLET sender
        // (`address(0xdead)` from the parent), already registered with
        // `verifierPubkey`. Slots 1..N-1 are fresh addresses needing
        // first-time registration before the campaign starts.
        address[] memory poolWallets = new address[](WALLET_POOL_SIZE);
        WOTSPlus.WinternitzAddress[] memory initialPubs = new WOTSPlus.WinternitzAddress[](WALLET_POOL_SIZE);
        bytes32[] memory initialPrivs = new bytes32[](WALLET_POOL_SIZE);

        poolWallets[0] = WALLET;
        initialPubs[0] = verifierPubkey;
        initialPrivs[0] = verifierPrivateKey;

        for (uint256 i = 1; i < WALLET_POOL_SIZE; i++) {
            poolWallets[i] = makeAddr(string.concat("paymaster-wallet-", _u2s(i)));
            (initialPubs[i], initialPrivs[i]) = _generateKeyPair(keccak256(abi.encodePacked("paymaster-init-key", i)));
        }

        // Pre-register the remaining wallets BEFORE transferring
        // ownership — ADMIN still holds the owner role here.
        vm.startPrank(ADMIN);
        for (uint256 i = 1; i < WALLET_POOL_SIZE; i++) {
            paymaster.setPqVerifier(poolWallets[i], initialPubs[i]);
        }
        paymaster.transferOwnership(address(handler));
        vm.stopPrank();

        handler.initialize(
            QuipPaymasterInvariantHandler.InitParams({
                paymaster: paymaster, wallets: poolWallets, initialPubs: initialPubs, initialPrivs: initialPrivs
            })
        );
    }

    /// @dev Override `QuipPaymasterTest.test_setUp` because ownership has
    ///      moved to the handler and the verifier pool spans N wallets,
    ///      not just the inherited WALLET.
    function test_setUp() public view override {
        assertEq(paymaster.owner(), address(handler));
        assertEq(handler.walletCount(), WALLET_POOL_SIZE);
        // First pool slot is the inherited WALLET — its verifier was
        // registered by the parent's setUp.
        WOTSPlus.WinternitzAddress memory v = paymaster.getPqVerifier(WALLET);
        assertEq(v.publicSeed, verifierPubkey.publicSeed);
        assertEq(v.publicKeyHash, verifierPubkey.publicKeyHash);
    }

    /// @dev Tiny uint-to-string helper for `makeAddr` labels. Pool is
    ///      small (< 10) so single-digit conversion suffices.
    function _u2s(uint256 v) internal pure returns (string memory) {
        require(v < 10, "_u2s only handles single digits");
        bytes memory b = new bytes(1);
        b[0] = bytes1(uint8(48 + v));
        return string(b);
    }
}
