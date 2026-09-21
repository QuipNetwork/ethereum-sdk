// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {ShrincsWallet_Local_Invariant} from "./Local.t.sol";

/// forge-config: default.invariant.fail-on-revert = true

/// @title ShrincsWallet — Strict Invariant Twin (fail on revert)
/// @dev Re-runs the Local suite with `fail_on_revert`. Every fuzzed selector
///      must complete at handler level; expected reverts are caught inside
///      the handler and counted, so any uncaught revert fails this run.
contract ShrincsWallet_Strict_Invariant is ShrincsWallet_Local_Invariant {}
