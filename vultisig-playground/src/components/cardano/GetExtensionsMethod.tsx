import { useState } from 'react'
import type { MethodComponentProps } from './types'
import { formatCip30Error, getEnabledApi } from './cardanoUtils'

export function GetExtensionsMethod({ provider, onResult, onError }: MethodComponentProps) {
  const [loading, setLoading] = useState(false)

  const handleClick = async () => {
    setLoading(true)
    try {
      const api = await getEnabledApi(provider)
      const extensions = await api.getExtensions()
      onResult(extensions)
    } catch (err) {
      onError(formatCip30Error(err))
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="space-y-3">
      <p className="text-xs text-gray-600">
        Returns the list of active CIP-30 extensions the wallet has enabled.
      </p>
      <button
        onClick={handleClick}
        disabled={loading}
        className="w-full px-4 py-2 text-sm bg-blue-600 text-white rounded hover:bg-blue-700 disabled:bg-gray-400 disabled:cursor-not-allowed transition-colors"
      >
        {loading ? 'Fetching…' : 'Call getExtensions()'}
      </button>
    </div>
  )
}
