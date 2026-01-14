import { useState } from 'react'
import type { SolanaWalletProvider } from './types'

interface PublicKeyMethodProps {
  provider: unknown
  onResult: (result: unknown) => void
  onError: (error: string) => void
  onAccountUpdate?: (accounts: string[]) => void
}

export function PublicKeyMethod({ onResult, onError }: PublicKeyMethodProps) {
  const [loading, setLoading] = useState<boolean>(false)

  const handleExecute = async (): Promise<void> => {
    const solanaProvider = window.vultisig?.solana as SolanaWalletProvider | undefined
    if (!solanaProvider) {
      onError('Solana provider not available')
      return
    }

    setLoading(true)
    try {
      if (solanaProvider.publicKey === undefined || solanaProvider.publicKey === null) {
        throw new Error('publicKey is not available. Please connect first.')
      }

      let publicKey: string
      if (typeof solanaProvider.publicKey === 'string') {
        publicKey = solanaProvider.publicKey
      } else if (typeof solanaProvider.publicKey === 'object' && 'toString' in solanaProvider.publicKey) {
        publicKey = solanaProvider.publicKey.toString()
      } else {
        throw new Error('publicKey format is not recognized')
      }

      onResult({ publicKey })
    } catch (err) {
      onError((err as Error).message || 'Unknown error')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="space-y-3">
      <p className="text-xs text-gray-600">
        Get public key of connected wallet
      </p>
      <button
        onClick={handleExecute}
        disabled={loading}
        className="w-full px-4 py-2 text-sm bg-blue-600 text-white rounded hover:bg-blue-700 disabled:bg-gray-400 disabled:cursor-not-allowed transition-colors"
      >
        {loading ? 'Loading...' : 'Get Public Key'}
      </button>
    </div>
  )
}

