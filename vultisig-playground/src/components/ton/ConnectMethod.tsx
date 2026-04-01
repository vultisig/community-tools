import { useState } from 'react'
import type { TonConnectBridge } from './types'

interface ConnectMethodProps {
  provider: unknown
  onResult: (result: unknown) => void
  onError: (error: string) => void
}

export function ConnectMethod({ provider, onResult, onError }: ConnectMethodProps) {
  const [loading, setLoading] = useState(false)
  const manifestUrl = `${window.location.origin}/tonconnect-manifest.json`

  const handleConnect = async () => {
    const bridge = provider as TonConnectBridge
    if (!bridge?.connect) {
      onError('TonConnect bridge not available')
      return
    }

    setLoading(true)
    try {
      const result = await bridge.connect(2, {
        manifestUrl,
        items: [{ name: 'ton_addr' }],
      })

      if (result.event === 'connect_error') {
        onError(`Connection error (code ${result.payload.code}): ${result.payload.message}`)
      } else {
        onResult(result.payload)
      }
    } catch (err) {
      onError((err as Error).message || 'Unknown error')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="space-y-3">
      <p className="text-xs text-gray-600">
        Connect to TON wallet using TonConnect v2 protocol.
      </p>
      <button
        onClick={handleConnect}
        disabled={loading}
        className="w-full px-4 py-2 text-sm bg-blue-600 text-white rounded hover:bg-blue-700 disabled:bg-gray-400 disabled:cursor-not-allowed transition-colors"
      >
        {loading ? 'Connecting...' : 'Connect'}
      </button>
    </div>
  )
}
