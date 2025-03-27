"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.QUIP_FACTORY_ADDRESS = exports.WOTS_PLUS_ADDRESS = void 0;
const addresses_json_1 = __importDefault(require("./addresses.json"));
exports.WOTS_PLUS_ADDRESS = addresses_json_1.default.WOTSPlus;
exports.QUIP_FACTORY_ADDRESS = addresses_json_1.default.QuipFactory;
