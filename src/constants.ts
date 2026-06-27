// Copyright (C) 2025 quip.network
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// TODO: Verify WOTSPLUS_GAS_ESTIMATE is still accurate against current contract — may be consumed by frontend
export const WOTSPLUS_GAS_ESTIMATE = 850_000;
// TODO: Verify DEFAULT_CONFIRMATIONS is still used — may be consumed by frontend
export const DEFAULT_CONFIRMATIONS = 1;

// TODO: Verify ERRORS are still accurate against current contract — may be consumed by frontend
export const ERRORS = {
  INVALID_NETWORK: "Invalid network specified",
  INSUFFICIENT_BALANCE: "Insufficient balance",
  UNAUTHORIZED: "Unauthorized operation",
} as const;
