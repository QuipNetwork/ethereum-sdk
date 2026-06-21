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

// `loadShrincsWasm` resolves to the Node loader by default. Browser bundlers
// substitute `loader.browser.js` for `loader.node.js` via the package
// `"browser"` field (see package.json), so neither `node:module` nor the CJS
// target's `fs` access reaches a browser bundle. Both loaders expose the same
// async `loadShrincsWasm(): Promise<ShrincsWasmModule>` signature.
export { loadShrincsWasm } from "./loader.node.js";
export type { ShrincsWasmModule, WasmShrincsKeypair } from "./types.js";
