import { useState } from 'react'
import type { CardanoPaginate, MethodComponentProps } from './types'
import {
  decodeCardanoUtxo,
  formatCip30Error,
  formatLovelace,
  getEnabledApi,
  hexPreview,
} from './cardanoUtils'
import { fromHex } from './cbor'

export function GetUtxosMethod({ provider, onResult, onError }: MethodComponentProps) {
  const [loading, setLoading] = useState(false)
  const [amount, setAmount] = useState('')
  const [page, setPage] = useState('')
  const [limit, setLimit] = useState('')

  const handleClick = async () => {
    setLoading(true)
    try {
      const api = await getEnabledApi(provider)
      let paginate: CardanoPaginate | undefined
      if (page.trim() && limit.trim()) {
        paginate = { page: Number(page), limit: Number(limit) }
      }
      const utxos = await api.getUtxos(amount.trim() || undefined, paginate)

      if (!utxos) {
        onResult({ note: 'Wallet has no UTXOs (or insufficient for requested amount)', utxos: null })
        return
      }

      const decoded = utxos.map((hex) => {
        const u = decodeCardanoUtxo(fromHex(hex))
        return {
          raw: hexPreview(hex, 20),
          txHash: u.txHash,
          outputIndex: u.outputIndex,
          address: hexPreview(u.address, 16),
          lovelace: formatLovelace(BigInt(u.value.lovelace)),
          assets: u.value.assets,
        }
      })
      onResult({ count: utxos.length, utxos: decoded, rawHexes: utxos })
    } catch (err) {
      onError(formatCip30Error(err))
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="space-y-3">
      <p className="text-xs text-gray-600">
        Returns hex-encoded UTXOs. Optional `amount` (hex CBOR Value) for coin selection; optional pagination.
      </p>
      <div>
        <label className="block text-xs font-medium text-gray-700 mb-1">
          Amount CBOR hex (optional)
        </label>
        <input
          type="text"
          value={amount}
          onChange={(e) => setAmount(e.target.value)}
          placeholder="e.g. 1a00989680 (= 10 ADA lovelace-only)"
          className="w-full px-3 py-2 text-xs font-mono border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
        />
        <p className="text-xs text-gray-500 mt-1">
          Leave blank to return all UTXOs. Otherwise the wallet tries to coin-select a covering subset.
        </p>
      </div>
      <div className="grid grid-cols-2 gap-2">
        <div>
          <label className="block text-xs font-medium text-gray-700 mb-1">Page (optional)</label>
          <input
            type="number"
            min="0"
            value={page}
            onChange={(e) => setPage(e.target.value)}
            placeholder="e.g. 0"
            className="w-full px-3 py-2 text-xs font-mono border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
          />
        </div>
        <div>
          <label className="block text-xs font-medium text-gray-700 mb-1">Limit (optional)</label>
          <input
            type="number"
            min="1"
            value={limit}
            onChange={(e) => setLimit(e.target.value)}
            placeholder="e.g. 5"
            className="w-full px-3 py-2 text-xs font-mono border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
          />
        </div>
      </div>
      <button
        onClick={handleClick}
        disabled={loading}
        className="w-full px-4 py-2 text-sm bg-blue-600 text-white rounded hover:bg-blue-700 disabled:bg-gray-400 disabled:cursor-not-allowed transition-colors"
      >
        {loading ? 'Fetching…' : 'Call getUtxos()'}
      </button>
    </div>
  )
}
