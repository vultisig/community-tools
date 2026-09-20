import assert from "node:assert/strict";
import { deriveECDSACoins, deriveEdDSACoins } from "./derive.js";

const privKeyHex = "0806a352d32950671e711225514a5fd53d6411dc9f4525d7bad11ef73956c601";
const chainCodeHex = "e2f8c4826d6d23407cff45498b940f52756c3056fa1bcba0cb7f6bafc2478eac";

// The demo Schnorr export is the little-endian scalar of the vault public key below.
const eddsaExportHex = "733da00cb116e47317d8d0fdf2629f11500abd28a52a8dcbb3f8737f2a631e07";
const eddsaScalarHex = "071e632a7f73f8b3cb8d2aa528bd0a50119f62f2fdd0d81773e416b10ca03d73";
const eddsaPubKeyHex = "20e368bf985efdc270500c6e9dc1159102323ff6eabab56f8fa9798e4ac0e2a9";

// Derived with the Go implementation (pkg/derive), not with this code.
const solanaAddress = "3DPAkfuk5bkh1c1Pg5GN57Gr6cSJsZHVBcJLTFMapmA8";
const tonAddress = "UQBzI_4nPOWMLkQFIjs7c76O43TGJhOrcJY7Zq5Yj-OWwKhm";
const suiAddress = "0xdf86603d1e457c5c95c18ff8dd9e921e349b7e587fdf6ac032b1b279bfe3241a";

const ecdsaKeys = deriveECDSACoins(privKeyHex, chainCodeHex);
const byName = Object.fromEntries(ecdsaKeys.map((k) => [k.name, k]));

const btc = byName.bitcoin;
assert.equal(btc.address, "bc1q0pap5flkh45w8zz2ew9xpf884me55g65l7vqcu", "BTC address");
assert.notEqual(btc.wifPrivateKey, "", "BTC WIF should not be empty");

const eth = byName.ethereum;
assert.equal(eth.address, "0x60790246e37D154e02beaF2b9Fb27F93a26A6B3f", "ETH address");
assert.equal(
  eth.hexPrivateKey,
  "e49960641cf0f56139fe8a3088cf7bf8bb0d4bb9ee94b788875834d604703623",
  "ETH private key",
);

assert.equal(byName.thorchain.address, "thor167h7nq5wuklekdeyrmsgy2p6gc3acaezp0wwql", "THOR address");
assert.equal(byName.maya.address, "maya167h7nq5wuklekdeyrmsgy2p6gc3acaezpcszk0", "MAYA address");

// Same demo root as pkg/derive/ripple_test.go; pins browser/native XRP parity.
assert.equal(byName.ripple.address, "rDLY568PwDwGGzi7qVRg1KVPj7AV2qsCCt", "XRP address");

for (const name of ["avalanche", "bsc", "arbitrum", "base", "optimism", "polygon"]) {
  assert.equal(byName[name].address, eth.address, `${name} should match ETH`);
}

const eddsaKeys = deriveEdDSACoins(eddsaExportHex, eddsaPubKeyHex);
const edByName = Object.fromEntries(eddsaKeys.map((k) => [k.name, k]));

const sol = edByName.solana;
assert.equal(sol.hexPublicKey, eddsaPubKeyHex, "EdDSA public key");
assert.equal(sol.hexPrivateKey, eddsaScalarHex, "EdDSA private key must be the canonical big-endian scalar");
assert.equal(sol.address, solanaAddress, "Solana address");
assert.equal(edByName.ton.address, tonAddress, "TON address");
assert.equal(edByName.sui.address, suiAddress, "SUI address");

console.log(`ECDSA coins derived: ${ecdsaKeys.length}`);
console.log(`BTC: ${btc.address}`);
console.log(`ETH: ${eth.address}`);
console.log(`EdDSA coins derived: ${eddsaKeys.length}`);
console.log(`EdDSA public key: ${sol.hexPublicKey}`);
console.log(`SOL: ${sol.address}`);
console.log(`TON: ${edByName.ton.address}`);
console.log(`SUI: ${edByName.sui.address}`);

assert.throws(() => deriveEdDSACoins(eddsaExportHex, `ff${eddsaPubKeyHex.slice(2)}`), /does not match/);
assert.throws(() => deriveEdDSACoins(eddsaExportHex), /required/);
assert.throws(() => deriveEdDSACoins(eddsaExportHex.slice(0, 62), eddsaPubKeyHex), /32 bytes/);
assert.throws(() => deriveEdDSACoins("00".repeat(32), eddsaPubKeyHex), /zero/);

console.log("All derive tests passed");
