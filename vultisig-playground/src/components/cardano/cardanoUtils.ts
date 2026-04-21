import { decode as cborDecode } from 'cbor-x'
import type { CardanoCip30ApiError, CardanoCip30FullApi, CardanoCip30InitialApi } from './types'
import { fromHex } from './cbor'

/**
 * Calls provider.enable() to retrieve the CIP-30 full API.
 * enable() is idempotent per CIP-30: after initial user approval it returns
 * immediately without re-prompting.
 */
export async function getEnabledApi(provider: unknown): Promise<CardanoCip30FullApi> {
  const initial = provider as CardanoCip30InitialApi | null
  if (!initial || typeof initial.enable !== 'function') {
    throw new Error('Cardano CIP-30 provider is not available')
  }
  return initial.enable()
}

/**
 * Formats errors thrown by CIP-30 methods (typed `{code, info}`) into a string.
 * Falls back to plain Error messages.
 */
export function formatCip30Error(err: unknown): string {
  if (err && typeof err === 'object' && 'code' in err && 'info' in err) {
    const e = err as CardanoCip30ApiError
    const max = e.maxSize !== undefined ? ` (maxSize: ${e.maxSize})` : ''
    return `[code ${e.code}] ${e.info}${max}`
  }
  if (err instanceof Error) return err.message
  return String(err)
}

/** Formats lovelace (bigint) as ADA with 6 decimal places. */
export function formatLovelace(lovelace: bigint | number): string {
  const v = typeof lovelace === 'bigint' ? lovelace : BigInt(lovelace)
  const whole = v / 1_000_000n
  const frac = v % 1_000_000n
  return `${whole.toString()}.${frac.toString().padStart(6, '0')} ADA`
}

type MultiAsset = Map<Uint8Array, Map<Uint8Array, bigint | number>>

type DecodedValue = bigint | number | [bigint | number, MultiAsset]

interface DecodedAsset {
  policyId: string
  assetName: string
  quantity: string
}

interface DecodedBalance {
  lovelace: string
  assets: DecodedAsset[]
}

function toHexLocal(bytes: Uint8Array): string {
  let hex = ''
  for (let i = 0; i < bytes.length; i++) {
    hex += bytes[i].toString(16).padStart(2, '0')
  }
  return hex
}

/** Decodes a CBOR value (lovelace-only uint OR [lovelace, multiasset]). */
export function decodeCardanoValue(bytes: Uint8Array): DecodedBalance {
  const decoded = cborDecode(bytes) as DecodedValue
  let lovelace: bigint
  let multiAsset: MultiAsset | null = null

  if (Array.isArray(decoded)) {
    lovelace = BigInt(decoded[0])
    multiAsset = decoded[1]
  } else {
    lovelace = BigInt(decoded)
  }

  const assets: DecodedAsset[] = []
  if (multiAsset instanceof Map) {
    for (const [policy, inner] of multiAsset.entries()) {
      if (!(inner instanceof Map)) continue
      for (const [name, qty] of inner.entries()) {
        assets.push({
          policyId: toHexLocal(policy),
          assetName: toHexLocal(name),
          quantity: BigInt(qty).toString(),
        })
      }
    }
  }

  return { lovelace: lovelace.toString(), assets }
}

export interface DecodedUtxo {
  txHash: string
  outputIndex: number
  address: string
  value: DecodedBalance
}

/**
 * Decodes a single CIP-30 UTXO (CBOR: `[[tx_hash, index], output]`).
 * `output` can be either a legacy array `[address, value]` or a post-Babbage
 * map with integer keys (0=address, 1=value).
 */
export function decodeCardanoUtxo(bytes: Uint8Array): DecodedUtxo {
  const decoded = cborDecode(bytes) as [[Uint8Array, number | bigint], unknown]
  const [[txHashBytes, indexRaw], output] = decoded

  let addressBytes: Uint8Array
  let valueDecoded: DecodedValue

  if (Array.isArray(output)) {
    addressBytes = output[0] as Uint8Array
    valueDecoded = output[1] as DecodedValue
  } else if (output instanceof Map) {
    addressBytes = output.get(0) as Uint8Array
    valueDecoded = output.get(1) as DecodedValue
  } else {
    throw new Error('Unsupported UTXO output format')
  }

  const balance = valueToBalance(valueDecoded)

  return {
    txHash: toHexLocal(txHashBytes),
    outputIndex: Number(indexRaw),
    address: toHexLocal(addressBytes),
    value: balance,
  }
}

function valueToBalance(decoded: DecodedValue): DecodedBalance {
  let lovelace: bigint
  let multiAsset: MultiAsset | null = null

  if (Array.isArray(decoded)) {
    lovelace = BigInt(decoded[0])
    multiAsset = decoded[1]
  } else {
    lovelace = BigInt(decoded)
  }

  const assets: DecodedAsset[] = []
  if (multiAsset instanceof Map) {
    for (const [policy, inner] of multiAsset.entries()) {
      if (!(inner instanceof Map)) continue
      for (const [name, qty] of inner.entries()) {
        assets.push({
          policyId: toHexLocal(policy),
          assetName: toHexLocal(name),
          quantity: BigInt(qty).toString(),
        })
      }
    }
  }

  return { lovelace: lovelace.toString(), assets }
}

/** Returns lovelace value of the largest lovelace-only UTXO, or null. */
export function pickLargestLovelaceUtxo(utxoHexes: string[]): {
  utxoHex: string
  decoded: DecodedUtxo
  lovelace: bigint
} | null {
  let best: { utxoHex: string; decoded: DecodedUtxo; lovelace: bigint } | null = null
  for (const hex of utxoHexes) {
    const decoded = decodeCardanoUtxo(fromHex(hex))
    if (decoded.value.assets.length > 0) continue
    const lovelace = BigInt(decoded.value.lovelace)
    if (!best || lovelace > best.lovelace) {
      best = { utxoHex: hex, decoded, lovelace }
    }
  }
  return best
}

/** Previews a hex string for display — shows first/last chars with length. */
export function hexPreview(hex: string, chars = 12): string {
  if (hex.length <= chars * 2 + 5) return hex
  return `${hex.slice(0, chars)}…${hex.slice(-chars)} (${hex.length / 2} bytes)`
}
