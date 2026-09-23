// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {ShrincsWallet_Local_Invariant} from "./Local.t.sol";

/// forge-config: default.invariant.fail-on-revert = true

contract ShrincsWallet_Strict_Invariant is ShrincsWallet_Local_Invariant {}
