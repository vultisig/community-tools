import { useState } from 'react'

interface RequestMethodProps {
  provider: unknown
  onResult: (result: unknown) => void
  onError: (error: string) => void
  onAccountUpdate?: (accounts: string[]) => void
}

function RequestMethodComponent({ onResult, onError, onAccountUpdate }: RequestMethodProps) {
  const [method] = useState<string>('tron_requestAccounts')
  const [loading, setLoading] = useState<boolean>(false)

  const handleExecute = async (): Promise<void> => {
    const tronProvider = window.vultisig?.tron
    if (!tronProvider) {
      onError('Tron provider not available')
      return
    }

    setLoading(true)
    try {
      const result = await tronProvider.request({
        method: 'tron_requestAccounts',
        params: [],
      })

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
      <div>
        <label className="block text-xs font-medium text-gray-700 mb-1">
          Method
        </label>
        <select
          value={method}
          disabled
          className="w-full px-3 py-2 text-xs font-mono border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 bg-gray-50 cursor-not-allowed"
        >
          <option value="tron_requestAccounts">
            tron_requestAccounts - Request user to connect Tron accounts
          </option>
        </select>
      </div>
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

export const RequestMethod = RequestMethodComponent

