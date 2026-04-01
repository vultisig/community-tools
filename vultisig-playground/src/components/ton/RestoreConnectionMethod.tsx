import { useState } from 'react'
import type { TonConnectBridge } from './types'

interface RestoreConnectionMethodProps {
  provider: unknown
  onResult: (result: unknown) => void
  onError: (error: string) => void
}

export function RestoreConnectionMethod({ provider, onResult, onError }: RestoreConnectionMethodProps) {
  const [loading, setLoading] = useState(false)

  const handleRestoreConnection = async () => {
    const bridge = provider as TonConnectBridge
    if (!bridge?.restoreConnection) {
      onError('TonConnect bridge not available')
      return
    }

    setLoading(true)
    try {
      const result = await bridge.restoreConnection()

      if (result.event === 'connect_error') {
        onError(`Restore failed (code ${result.payload.code}): ${result.payload.message}`)
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
        Restore an existing TonConnect session. Returns the wallet address and public key if a session exists.
      </p>
      <button
        onClick={handleRestoreConnection}
        disabled={loading}
        className="w-full px-4 py-2 text-sm bg-blue-600 text-white rounded hover:bg-blue-700 disabled:bg-gray-400 disabled:cursor-not-allowed transition-colors"
      >
        {loading ? 'Restoring...' : 'Restore Connection'}
      </button>
    </div>
  )
}
