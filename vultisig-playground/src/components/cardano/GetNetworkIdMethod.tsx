import { useState } from 'react'
import type { MethodComponentProps } from './types'
import { formatCip30Error, getEnabledApi } from './cardanoUtils'

export function GetNetworkIdMethod({ provider, onResult, onError }: MethodComponentProps) {
  const [loading, setLoading] = useState(false)

  const handleClick = async () => {
    setLoading(true)
    try {
      const api = await getEnabledApi(provider)
      const id = await api.getNetworkId()
      onResult({ networkId: id, label: id === 1 ? 'mainnet' : id === 0 ? 'testnet' : 'unknown' })
    } catch (err) {
      onError(formatCip30Error(err))
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="space-y-3">
      <p className="text-xs text-gray-600">Returns 1 for mainnet, 0 for testnet.</p>
      <button
        onClick={handleClick}
        disabled={loading}
        className="w-full px-4 py-2 text-sm bg-blue-600 text-white rounded hover:bg-blue-700 disabled:bg-gray-400 disabled:cursor-not-allowed transition-colors"
      >
        {loading ? 'Fetching…' : 'Call getNetworkId()'}
      </button>
    </div>
  )
}
