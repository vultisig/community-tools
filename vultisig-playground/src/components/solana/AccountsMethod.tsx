import { useState } from 'react'
import type { WalletAccount } from '@wallet-standard/base'
import type { SolanaWalletProvider } from './types'

interface AccountsMethodProps {
  provider: unknown
  onResult: (result: unknown) => void
  onError: (error: string) => void
  onAccountUpdate?: (accounts: string[]) => void
}

export function AccountsMethod({ onResult, onError, onAccountUpdate }: AccountsMethodProps) {
  const [loading, setLoading] = useState<boolean>(false)

  const handleExecute = async (): Promise<void> => {
    const solanaProvider = window.vultisig?.solana as SolanaWalletProvider | undefined
    if (!solanaProvider) {
      onError('Solana provider not available')
      return
    }

    setLoading(true)
    try {
      if (solanaProvider.accounts === undefined) {
        throw new Error('accounts property is not available')
      }

      const accounts = solanaProvider.accounts
      let result: WalletAccount[] | string[]
      
      if (Array.isArray(accounts)) {
        if (accounts.length > 0 && typeof accounts[0] === 'object' && 'address' in accounts[0]) {
          result = (accounts as WalletAccount[]).map(acc => acc.address)
        } else {
          result = [...accounts] as string[]
        }
      } else {
        result = accounts as string[]
      }

      onResult(result)

      if (onAccountUpdate && Array.isArray(result)) {
        onAccountUpdate(result)
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
        Get connected accounts (readonly property)
      </p>
      <button
        onClick={handleExecute}
        disabled={loading}
        className="w-full px-4 py-2 text-sm bg-blue-600 text-white rounded hover:bg-blue-700 disabled:bg-gray-400 disabled:cursor-not-allowed transition-colors"
      >
        {loading ? 'Loading...' : 'Get Accounts'}
      </button>
    </div>
  )
}

