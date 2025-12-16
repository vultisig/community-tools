import { useState, useCallback } from 'react'

interface RequestMethodProps {
  provider: unknown
  onResult: (result: unknown) => void
  onError: (error: string) => void
  onAccountUpdate?: (accounts: string[]) => void
}

const availableMethods = [
  { value: 'get_accounts', label: 'get_accounts', description: 'Get currently connected accounts' },
  { value: 'request_accounts', label: 'request_accounts', description: 'Request user to connect accounts' },
]

function RequestMethodComponent({ onResult, onError, onAccountUpdate }: RequestMethodProps) {
  const [method, setMethod] = useState<string>('get_accounts')
  const [params, setParams] = useState<string>('[]')
  const [loading, setLoading] = useState<boolean>(false)

  const handleExecute = async (): Promise<void> => {

    setLoading(true)
    try {
      const result = await window.vultisig?.bitcoin?.request({
        method,
      })

      onResult(result)

      if ((method === 'get_accounts' || method === 'request_accounts') && onAccountUpdate) {
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
          onChange={(e) => setMethod(e.target.value)}
          className="w-full px-3 py-2 text-xs font-mono border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 bg-white"
        >
          {availableMethods.map((m) => (
            <option key={m.value} value={m.value}>
              {m.label} - {m.description}
            </option>
          ))}
        </select>
      </div>
      <div>
        <label className="block text-xs font-medium text-gray-700 mb-1">
          Params (JSON array)
        </label>
        <textarea
          value={params}
          onChange={(e) => setParams(e.target.value)}
          placeholder="[]"
          className="w-full px-3 py-2 text-xs font-mono border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 resize-y min-h-[60px]"
          rows={3}
        />
      </div>
      <button
        onClick={handleExecute}
        disabled={loading || !method}
        className="w-full px-4 py-2 text-sm bg-blue-600 text-white rounded hover:bg-blue-700 disabled:bg-gray-400 disabled:cursor-not-allowed transition-colors"
      >
        {loading ? 'Executing...' : 'Execute Request'}
      </button>
    </div>
  )
}

export const RequestMethod = RequestMethodComponent

