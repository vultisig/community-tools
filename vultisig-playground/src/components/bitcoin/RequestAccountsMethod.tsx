import { useState } from 'react'

interface RequestAccountsMethodProps {
  provider: unknown
  onResult: (result: unknown) => void
  onError: (error: string) => void
  onAccountUpdate?: (accounts: string[]) => void
}

export function RequestAccountsMethod({ onResult, onError, onAccountUpdate }: RequestAccountsMethodProps) {
  const [loading, setLoading] = useState<boolean>(false)

  const handleExecute = async (): Promise<void> => {
    const btcProvider = window.vultisig?.bitcoin
    if (!btcProvider) {
      onError('Provider not available')
      return
    }

    setLoading(true)
    try {
      const providerObj = btcProvider as unknown as Record<string, unknown>


      const result = await (providerObj.requestAccounts as () => Promise<unknown>)()

      onResult(result)

      if (onAccountUpdate) {
        const accounts = result as string[]
        if (Array.isArray(accounts)) {
          onAccountUpdate(accounts)
        }
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
        Request user to connect their Bitcoin wallet
      </p>
      <button
        onClick={handleExecute}
        disabled={loading}
        className="w-full px-4 py-2 text-sm bg-blue-600 text-white rounded hover:bg-blue-700 disabled:bg-gray-400 disabled:cursor-not-allowed transition-colors"
      >
        {loading ? 'Requesting...' : 'Request Accounts'}
      </button>
    </div>
  )
}

