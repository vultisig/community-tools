import { useState } from 'react'
import type { SolanaWalletProvider } from './types'

interface IsConnectedMethodProps {
  provider: unknown
  onResult: (result: unknown) => void
  onError: (error: string) => void
  onAccountUpdate?: (accounts: string[]) => void
}

export function IsConnectedMethod({ onResult, onError }: IsConnectedMethodProps) {
  const [loading, setLoading] = useState<boolean>(false)

  const handleExecute = async (): Promise<void> => {
    const solanaProvider = window.vultisig?.solana as SolanaWalletProvider | undefined
    if (!solanaProvider) {
      onError('Solana provider not available')
      return
    }

    setLoading(true)
    try {
      let result: boolean
      if (typeof solanaProvider.isConnected === 'boolean') {
        result = solanaProvider.isConnected
      } else if (typeof solanaProvider.isConnected === 'function') {
        result = await solanaProvider.isConnected()
      } else {
        throw new Error('isConnected property/method is not available')
      }

      onResult({ isConnected: result })
    } catch (err) {
      onError((err as Error).message || 'Unknown error')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="space-y-3">
      <p className="text-xs text-gray-600">
        Check if wallet is connected
      </p>
      <button
        onClick={handleExecute}
        disabled={loading}
        className="w-full px-4 py-2 text-sm bg-blue-600 text-white rounded hover:bg-blue-700 disabled:bg-gray-400 disabled:cursor-not-allowed transition-colors"
      >
        {loading ? 'Checking...' : 'Check Connection'}
      </button>
    </div>
  )
}

