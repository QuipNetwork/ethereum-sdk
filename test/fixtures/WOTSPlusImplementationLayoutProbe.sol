// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {WOTSPlusStorage} from "../../contracts/wots/WOTSPlusStorage.sol";

/// @dev Test-only probe whose sole purpose is to expose `WOTSPlusStorage.Layout`
///      to `forge inspect storageLayout`. ERC-7201 namespaced storage is invisible
///      to `forge inspect` because it isn't a declared top-level state variable;
///      coercing the struct into a public state var makes solc emit the full
///      slot/offset breakdown for every field — which we then snapshot as a JSON
///      fixture and diff in CI.
///
///      DO NOT INSTANTIATE. This contract has no behaviour. Its bytecode is
///      irrelevant; only the storageLayout artifact is consumed.
contract WOTSPlusImplementationLayoutProbe {
    WOTSPlusStorage.Layout public layout;
}
