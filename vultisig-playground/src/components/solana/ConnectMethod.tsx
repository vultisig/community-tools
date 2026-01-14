import { useState } from 'react'
import type { SolanaWalletProvider } from './types'

interface ConnectMethodProps {
  provider: unknown
  onResult: (result: unknown) => void
  onError: (error: string) => void
  onAccountUpdate?: (accounts: string[]) => void
}

export function ConnectMethod({ onResult, onError, onAccountUpdate }: ConnectMethodProps) {
  const [loading, setLoading] = useState<boolean>(false)

  const handleConnect = async (): Promise<void> => {
    const solanaProvider = window.vultisig?.solana as SolanaWalletProvider | undefined
    if (!solanaProvider) {
      onError('Solana provider not available')
      return
    }

    setLoading(true)
    try {
      if (!solanaProvider.connect || typeof solanaProvider.connect !== 'function') {
        throw new Error('connect method is not available')
      }

      const result = await solanaProvider.connect()
      const publicKey = result.publicKey.toString()

      onResult({ publicKey })

      if (onAccountUpdate) {
        onAccountUpdate([publicKey])
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
        Connect to Solana wallet
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

