export type UtxoNetwork = 'BTC' | 'BCH' | 'DOGE' | 'LTC'

export interface Utxo {
  index: number
  hash: string
  value: bigint
}

export type UtxoWithHex = Utxo & { hex?: string }

type BlockchairChain = 'bitcoin' | 'bitcoin-cash' | 'dogecoin' | 'litecoin'

export function utxoNetworkTochain(network: UtxoNetwork): BlockchairChain {
  switch (network) {
    case 'BTC':
      return 'bitcoin'
    case 'BCH':
      return 'bitcoin-cash'
    case 'DOGE':
      return 'dogecoin'
    case 'LTC':
      return 'litecoin'
    default:
      throw new Error(`Unsupported UTXO network: ${network}`)
  }
}

// Vultisig's Blockchair proxy — the same source the Vultisig SDK / extension use
// for UTXO lookups. Override with VITE_BLOCKCHAIR_URL to point at another
// Blockchair-compatible host.
const BLOCKCHAIR_URL = import.meta.env.VITE_BLOCKCHAIR_URL || 'https://api.vultisig.com/blockchair'

// Blockchair caps dashboards/address at 1000 UTXOs per page.
const UTXO_PAGE_SIZE = 1000

// Raw tx hex is fetched one txid at a time (the proxy does not accept
// Blockchair's comma-separated batch form), so bound the fan-out.
const RAW_TX_CONCURRENCY = 5

interface BlockchairAddressResponse {
  data: Record<
    string,
    {
      address?: { unspent_output_count?: number }
      utxo: Array<{
        transaction_hash: string
        index: number
        value: number
      }>
    }
  >
}

interface BlockchairRawTxResponse {
  data: Record<string, { raw_transaction: string }>
}

async function getJson<T>(url: string): Promise<T> {
  const response = await fetch(url)
  if (!response.ok) {
    throw new Error(`Blockchair request failed (${response.status}) for ${url}`)
  }
  return response.json() as Promise<T>
}

async function mapWithConcurrency<T, R>(
  items: T[],
  limit: number,
  fn: (item: T) => Promise<R>
): Promise<R[]> {
  const results: R[] = new Array(items.length)
  let next = 0
  const workers = Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (next < items.length) {
      const i = next++
      results[i] = await fn(items[i])
    }
  })
  await Promise.all(workers)
  return results
}

export class UtxoQueryClient {
  private chain: BlockchairChain
  private address: string

  constructor(network: UtxoNetwork, address: string) {
    this.chain = utxoNetworkTochain(network)
    // Blockchair keys BCH by the bare cashaddr; the `bitcoincash:` prefix
    // form is not routable through the proxy.
    this.address = network === 'BCH' ? address.replace(/^bitcoincash:/i, '') : address
  }

  async fetch(): Promise<UtxoWithHex[]> {
    const utxos = await this.fetchUtxos()
    if (utxos.length === 0) {
      return []
    }

    // Every PSBT input here is built with nonWitnessUtxo, so each UTXO needs
    // the full hex of the transaction that created it.
    const txids = [...new Set(utxos.map((u) => u.hash))]
    const hexes = await mapWithConcurrency(txids, RAW_TX_CONCURRENCY, (txid) => this.fetchRawTx(txid))
    const hexByTxid = new Map(txids.map((txid, i) => [txid, hexes[i]]))

    return utxos.map((utxo) => ({ ...utxo, hex: hexByTxid.get(utxo.hash) }))
  }

  private async fetchUtxos(): Promise<Utxo[]> {
    const utxos: Utxo[] = []

    for (let offset = 0; ; offset += UTXO_PAGE_SIZE) {
      const url = `${BLOCKCHAIR_URL}/${this.chain}/dashboards/address/${this.address}?limit=${UTXO_PAGE_SIZE}&offset=${offset}`
      const page = await getJson<BlockchairAddressResponse>(url)
      const entry = page.data?.[this.address] ?? Object.values(page.data ?? {})[0]
      const pageUtxos = entry?.utxo ?? []

      for (const u of pageUtxos) {
        utxos.push({ hash: u.transaction_hash, index: u.index, value: BigInt(u.value) })
      }

      const expected = entry?.address?.unspent_output_count
      const done =
        pageUtxos.length < UTXO_PAGE_SIZE || (expected !== undefined && utxos.length >= expected)
      if (done) {
        break
      }
    }

    return utxos
  }

  private async fetchRawTx(txid: string): Promise<string> {
    const url = `${BLOCKCHAIR_URL}/${this.chain}/raw/transaction/${txid}`
    const result = await getJson<BlockchairRawTxResponse>(url)
    const hex = result.data?.[txid]?.raw_transaction
    if (!hex) {
      throw new Error(`Raw transaction hex not available for ${txid}`)
    }
    return hex
  }
}
