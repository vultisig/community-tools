import { useState } from 'react'
import type { SolanaWalletProvider } from './types'

interface DisconnectMethodProps {
  provider: unknown
  onResult: (result: unknown) => void
  onError: (error: string) => void
  onAccountUpdate?: (accounts: string[]) => void
}

export function DisconnectMethod({ onResult, onError }: DisconnectMethodProps) {
  const [loading, setLoading] = useState<boolean>(false)

  const handleExecute = async (): Promise<void> => {
    const solanaProvider = window.vultisig?.solana as SolanaWalletProvider | undefined
    if (!solanaProvider) {
      onError('Solana provider not available')
      return
    }

    setLoading(true)
    try {
      if (!solanaProvider.disconnect || typeof solanaProvider.disconnect !== 'function') {
        throw new Error('disconnect method is not available')
      }

      await solanaProvider.disconnect()
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
        Disconnect from Solana wallet
      </p>
      <button
        onClick={handleExecute}
        disabled={loading}
        className="w-full px-4 py-2 text-sm bg-blue-600 text-white rounded hover:bg-blue-700 disabled:bg-gray-400 disabled:cursor-not-allowed transition-colors"
      >
        {loading ? 'Disconnecting...' : 'Disconnect'}
      </button>
    </div>
  )
}

