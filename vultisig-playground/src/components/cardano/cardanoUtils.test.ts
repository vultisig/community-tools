import assert from 'node:assert/strict'
import { describe, it } from 'node:test'
import { decodeCardanoUtxo, decodeCardanoValue, pickLargestLovelaceUtxo } from './cardanoUtils.ts'
import { cborArray, cborBytes, cborMap, cborUint, toHex } from './cbor.ts'

const txHash = new Uint8Array(32).fill(0xab)
const address = new Uint8Array(29).fill(0x01)
const policyId = new Uint8Array(28).fill(0xcc)
const assetName = new TextEncoder().encode('TOKEN')

const lovelaceOnly = cborUint(4_058_050n)

// [lovelace, { policy_id => { asset_name => quantity } }] — byte-string map keys
const multiAsset = cborArray([
  cborUint(2_000_000n),
  cborMap([[cborBytes(policyId), cborMap([[cborBytes(assetName), cborUint(42n)]])]]),
])

const utxo = (index: bigint, output: Uint8Array) =>
  cborArray([cborArray([cborBytes(txHash), cborUint(index)]), output])

// Legacy (pre-Babbage) output: [address, value]
const legacyOutput = (value: Uint8Array) => cborArray([cborBytes(address), value])

// Babbage output: { 0: address, 1: value } — integer map keys
const babbageOutput = (value: Uint8Array) =>
  cborMap([
    [cborUint(0n), cborBytes(address)],
    [cborUint(1n), value],
  ])

describe('decodeCardanoValue', () => {
  it('decodes a lovelace-only value', () => {
    assert.deepEqual(decodeCardanoValue(lovelaceOnly), { lovelace: '4058050', assets: [] })
  })

  it('decodes a multi-asset value with byte-string map keys', () => {
    assert.deepEqual(decodeCardanoValue(multiAsset), {
      lovelace: '2000000',
      assets: [{ policyId: toHex(policyId), assetName: toHex(assetName), quantity: '42' }],
    })
  })
})

describe('decodeCardanoUtxo', () => {
  it('decodes a legacy array output carrying native tokens', () => {
    const decoded = decodeCardanoUtxo(utxo(0n, legacyOutput(multiAsset)))
    assert.equal(decoded.txHash, toHex(txHash))
    assert.equal(decoded.outputIndex, 0)
    assert.equal(decoded.address, toHex(address))
    assert.equal(decoded.value.lovelace, '2000000')
    assert.equal(decoded.value.assets.length, 1)
  })

  it('decodes a Babbage map output', () => {
    const decoded = decodeCardanoUtxo(utxo(1n, babbageOutput(lovelaceOnly)))
    assert.equal(decoded.outputIndex, 1)
    assert.equal(decoded.address, toHex(address))
    assert.deepEqual(decoded.value, { lovelace: '4058050', assets: [] })
  })

  it('decodes a Babbage map output carrying native tokens', () => {
    const decoded = decodeCardanoUtxo(utxo(2n, babbageOutput(multiAsset)))
    assert.equal(decoded.value.assets[0].policyId, toHex(policyId))
  })
})

describe('pickLargestLovelaceUtxo', () => {
  it('skips multi-asset UTXOs instead of throwing on them', () => {
    const hexes = [
      toHex(utxo(0n, legacyOutput(multiAsset))),
      toHex(utxo(1n, babbageOutput(cborUint(1_500_000n)))),
      toHex(utxo(2n, legacyOutput(lovelaceOnly))),
    ]
    const best = pickLargestLovelaceUtxo(hexes)
    assert.ok(best)
    assert.equal(best.decoded.outputIndex, 2)
    assert.equal(best.lovelace, 4_058_050n)
  })
})
