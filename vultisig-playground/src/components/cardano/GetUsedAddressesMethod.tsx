import { useState } from 'react'
import type { CardanoPaginate, MethodComponentProps } from './types'
import { formatCip30Error, getEnabledApi } from './cardanoUtils'

export function GetUsedAddressesMethod({ provider, onResult, onError }: MethodComponentProps) {
  const [loading, setLoading] = useState(false)
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
      const addresses = await api.getUsedAddresses(paginate)
      onResult(addresses)
    } catch (err) {
      onError(formatCip30Error(err))
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="space-y-3">
      <p className="text-xs text-gray-600">
        Returns hex-encoded addresses that have been used (received funds). Optional pagination.
      </p>
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
            placeholder="e.g. 10"
            className="w-full px-3 py-2 text-xs font-mono border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
          />
        </div>
      </div>
      <button
        onClick={handleClick}
        disabled={loading}
        className="w-full px-4 py-2 text-sm bg-blue-600 text-white rounded hover:bg-blue-700 disabled:bg-gray-400 disabled:cursor-not-allowed transition-colors"
      >
        {loading ? 'Fetching…' : 'Call getUsedAddresses()'}
      </button>
    </div>
  )
}
