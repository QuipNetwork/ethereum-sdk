// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {QuipFactoryTest} from "../QuipFactory.t.sol";
import {QuipFactoryInvariantHandler, FactoryImplStub} from "./Handler.t.sol";

/// @title QuipFactory Invariant Test Base
/// @dev Hands factory ownership to the fuzz Handler via Ownable2Step's
///      two-step handover so `onlyOwner` calls inside fuzz selectors
///      need no pranking. Seeds the Handler with a pool of pre-deployed
///      `FactoryImplStub` pairs — each pair shares a codehash so the
///      `vettedWalletImpls[codehash]` rebind path inside
///      `undeprecateImplementation` is reachable. Subclasses declare
///      `invariant_*` functions and call `targetContract(address(handler))`
///      from their own `setUp` after `super.setUp()`.
abstract contract QuipFactoryInvariantBase is QuipFactoryTest {
    QuipFactoryInvariantHandler public handler;

    /// @dev Pool size — eight (original, twin) pairs gives the fuzz tree
    ///      enough distinct codehashes to interleave deprecate /
    ///      undeprecate sequences without exhausting selectors. Each
    ///      `FactoryImplStub` costs ~30k gas to deploy, so 16 deployments
    ///      in setUp is negligible against the campaign budget.
    uint256 internal constant IMPL_POOL_SIZE = 8;

    function setUp() public virtual override {
        super.setUp();

        handler = new QuipFactoryInvariantHandler();

        // Ownable2Step handover: ADMIN initiates, handler accepts.
        // Post-accept, `factory.owner() == address(handler)` and every
        // fuzzed `onlyOwner` call resolves directly.
        vm.prank(ADMIN);
        factory.transferOwnership(address(handler));
        handler.acceptFactoryOwnership(factory);

        // Pre-deploy the (original, twin) pool. `id = i + 1` ensures each
        // slot's stubs have a distinct immutable value baked into runtime
        // bytecode, producing a distinct codehash per slot while the
        // two members of a slot share theirs.
        address[] memory pOriginals = new address[](IMPL_POOL_SIZE);
        address[] memory pTwins = new address[](IMPL_POOL_SIZE);
        for (uint256 i = 0; i < IMPL_POOL_SIZE; i++) {
            pOriginals[i] = address(new FactoryImplStub(i + 1));
            pTwins[i] = address(new FactoryImplStub(i + 1));
            // Sanity: confirm the pre-deploy invariant the handler relies on.
            require(
                pOriginals[i].codehash == pTwins[i].codehash,
                "pool twin codehash mismatch"
            );
            require(pOriginals[i] != pTwins[i], "pool address collision");
        }

        handler.initialize(
            factory,
            address(walletImplementation),
            pOriginals,
            pTwins
        );
    }

    /// @dev Adjusts the inherited `test_setUp` to reflect post-handover
    ///      ownership. The parent asserts `factory.owner() == ADMIN`,
    ///      which is no longer true after this base hands ownership off.
    function test_setUp() public view override {
        assertEq(factory.owner(), address(handler));
        assertEq(factory.creationFee(), 0);
        assertEq(factory.executeFee(), 0);
        assertEq(factory.MAX_FEE(), 0.1 ether);
        // walletImplementation was vetted by the parent's setUp before
        // ownership was transferred — the handler inherits a 1-entry set.
        assertEq(factory.getVettedCodeCount(), 1);
    }
}
