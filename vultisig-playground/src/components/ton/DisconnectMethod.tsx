import { useState } from 'react'
import type { TonConnectBridge } from './types'

interface DisconnectMethodProps {
  provider: unknown
  onResult: (result: unknown) => void
  onError: (error: string) => void
}

export function DisconnectMethod({ provider, onResult, onError }: DisconnectMethodProps) {
  const [loading, setLoading] = useState(false)

  const handleDisconnect = async () => {
    const bridge = provider as TonConnectBridge
    if (!bridge?.disconnect) {
      onError('TonConnect bridge not available')
      return
    }

    setLoading(true)
    try {
      await bridge.disconnect()
      onResult({ disconnected: true })
    } catch (err) {
      onError((err as Error).message || 'Unknown error')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="space-y-3">
      <p className="text-xs text-gray-600">
        Disconnect from the TON wallet. Ends the current TonConnect session.
      </p>
      <button
        onClick={handleDisconnect}
        disabled={loading}
        className="w-full px-4 py-2 text-sm bg-blue-600 text-white rounded hover:bg-blue-700 disabled:bg-gray-400 disabled:cursor-not-allowed transition-colors"
      >
        {loading ? 'Disconnecting...' : 'Disconnect'}
      </button>
    </div>
  )
}
