import {
  cborArray,
  cborBool,
  cborBytes,
  cborMap,
  cborNull,
  cborUint,
  fromHex,
  toHex,
} from './cbor'
import { pickLargestLovelaceUtxo } from './cardanoUtils'
import type { CardanoCip30FullApi } from './types'

const SAMPLE_FEE_LOVELACE = 200_000n // 0.2 ADA — safe overpay for a 1-in/1-out tx
const TTL_SLOT_BUFFER = 7_200 // ~2 hours on mainnet

const VULTISIG_CARDANO_TIP_URL = 'https://api.vultisig.com/cardano/tip'

async function fetchCurrentSlot(): Promise<number> {
  const response = await fetch(VULTISIG_CARDANO_TIP_URL, {
    headers: { accept: 'application/json' },
  })
  if (!response.ok) {
    throw new Error(
      `Vultisig cardano tip fetch failed: ${response.status} ${response.statusText}`
    )
  }
  const body = (await response.json()) as Array<{ abs_slot: number }>
  if (!Array.isArray(body) || body.length === 0 || typeof body[0].abs_slot !== 'number') {
    throw new Error('Vultisig cardano tip returned unexpected shape')
  }
  return body[0].abs_slot
}

export interface BuiltSampleTx {
  /** Full unsigned transaction CBOR (hex). This is what gets passed to signTx. */
  unsignedTxHex: string
  /** Raw body bytes — needed to rebuild the final signed tx after signing. */
  bodyBytes: Uint8Array
  inputTxHash: string
  inputIndex: number
  outputAddressHex: string
  outputLovelace: string
  feeLovelace: string
  ttl: number
}

/**
 * Builds a minimal self-transfer Cardano transaction using the connected
 * wallet's UTXOs and change address:
 *
 *   inputs:  largest lovelace-only UTXO
 *   outputs: [change_address → (utxo.amount - fee)]
 *   fee:     0.2 ADA (safe overpay)
 *   TTL:     current_slot + 7200
 *
 * The user can then sign this via signTx and combine with buildSignedTx().
 */
export async function buildSampleUnsignedTx(
  api: CardanoCip30FullApi
): Promise<BuiltSampleTx> {
  const [changeAddressHex, utxoHexes] = await Promise.all([
    api.getChangeAddress(),
    api.getUtxos(),
  ])

  if (!utxoHexes || utxoHexes.length === 0) {
    throw new Error('No UTXOs available. Fund the wallet first.')
  }

  const selected = pickLargestLovelaceUtxo(utxoHexes)
  if (!selected) {
    throw new Error('No lovelace-only UTXOs found (all UTXOs contain native assets).')
  }

  if (selected.lovelace <= SAMPLE_FEE_LOVELACE) {
    throw new Error(
      `Largest UTXO (${selected.lovelace} lovelace) is too small to cover the ${SAMPLE_FEE_LOVELACE} lovelace sample fee.`
    )
  }

  const outputLovelace = selected.lovelace - SAMPLE_FEE_LOVELACE
  const ttl = (await fetchCurrentSlot()) + TTL_SLOT_BUFFER

  const inputs = cborArray([
    cborArray([
      cborBytes(fromHex(selected.decoded.txHash)),
      cborUint(selected.decoded.outputIndex),
    ]),
  ])

  const outputs = cborArray([
    cborArray([cborBytes(fromHex(changeAddressHex)), cborUint(outputLovelace)]),
  ])

  const bodyBytes = cborMap([
    [cborUint(0), inputs],
    [cborUint(1), outputs],
    [cborUint(2), cborUint(SAMPLE_FEE_LOVELACE)],
    [cborUint(3), cborUint(ttl)],
  ])

  const emptyWitnessSet = cborMap([])
  const txBytes = cborArray([bodyBytes, emptyWitnessSet, cborBool(true), cborNull()])

  return {
    unsignedTxHex: toHex(txBytes),
    bodyBytes,
    inputTxHash: selected.decoded.txHash,
    inputIndex: selected.decoded.outputIndex,
    outputAddressHex: changeAddressHex,
    outputLovelace: outputLovelace.toString(),
    feeLovelace: SAMPLE_FEE_LOVELACE.toString(),
    ttl,
  }
}

/**
 * Combines a body (cached from buildSampleUnsignedTx) with the witness set
 * returned by signTx to produce a fully signed transaction CBOR.
 */
export function buildSignedTx(bodyBytes: Uint8Array, witnessSetHex: string): string {
  const witnessSet = fromHex(witnessSetHex)
  const tx = cborArray([bodyBytes, witnessSet, cborBool(true), cborNull()])
  return toHex(tx)
}
