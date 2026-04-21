import { useState } from 'react'
import type { CardanoCip30InitialApi, MethodComponentProps } from './types'
import { formatCip30Error } from './cardanoUtils'

export function IsEnabledMethod({ provider, onResult, onError }: MethodComponentProps) {
  const [loading, setLoading] = useState(false)

  const handleClick = async () => {
    const api = provider as CardanoCip30InitialApi
    setLoading(true)
    try {
      const result = await api.isEnabled()
      onResult(result)
    } catch (err) {
      onError(formatCip30Error(err))
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="space-y-3">
      <p className="text-xs text-gray-600">
        Returns true if the dApp already has connection access (no user prompt).
      </p>
      <button
        onClick={handleClick}
        disabled={loading}
        className="w-full px-4 py-2 text-sm bg-blue-600 text-white rounded hover:bg-blue-700 disabled:bg-gray-400 disabled:cursor-not-allowed transition-colors"
      >
        {loading ? 'Checking…' : 'Call isEnabled()'}
      </button>
    </div>
  )
}
