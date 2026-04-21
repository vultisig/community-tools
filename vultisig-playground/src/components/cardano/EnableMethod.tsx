import { useState } from 'react'
import type { CardanoCip30InitialApi, MethodComponentProps } from './types'
import { formatCip30Error } from './cardanoUtils'

export function EnableMethod({ provider, onResult, onError }: MethodComponentProps) {
  const [loading, setLoading] = useState(false)

  const handleClick = async () => {
    const api = provider as CardanoCip30InitialApi
    setLoading(true)
    try {
      const fullApi = await api.enable()
      onResult({
        connected: true,
        availableMethods: Object.keys(fullApi).sort(),
      })
    } catch (err) {
      onError(formatCip30Error(err))
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="space-y-3">
      <p className="text-xs text-gray-600">
        Requests connection to the wallet. First call shows the approval popup;
        subsequent calls return the full CIP-30 API immediately.
      </p>
      <div className="bg-gray-50 border border-gray-200 rounded p-2 text-xs text-gray-700">
        <span className="font-semibold">Wallet metadata:</span>{' '}
        <code className="font-mono">
          {JSON.stringify(
            {
              name: (provider as CardanoCip30InitialApi).name,
              apiVersion: (provider as CardanoCip30InitialApi).apiVersion,
              supportedExtensions: (provider as CardanoCip30InitialApi).supportedExtensions,
            },
            null,
            2
          )}
        </code>
      </div>
      <button
        onClick={handleClick}
        disabled={loading}
        className="w-full px-4 py-2 text-sm bg-blue-600 text-white rounded hover:bg-blue-700 disabled:bg-gray-400 disabled:cursor-not-allowed transition-colors"
      >
        {loading ? 'Enabling…' : 'Call enable()'}
      </button>
    </div>
  )
}
