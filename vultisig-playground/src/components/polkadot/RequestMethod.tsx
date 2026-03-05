import { useState } from 'react'

interface RequestMethodProps {
  provider: unknown
  onResult: (result: unknown) => void
  onError: (error: string) => void
  onAccountUpdate?: (accounts: string[]) => void
}

export function RequestMethod({ provider, onResult, onError, onAccountUpdate }: RequestMethodProps) {
  const [method, setMethod] = useState<string>('get_accounts')
  const [paramsJson, setParamsJson] = useState<string>('[]')
  const [loading, setLoading] = useState<boolean>(false)

  const handleExecute = async (): Promise<void> => {
    const providerObj = provider as Record<string, unknown> | null
    if (!providerObj) {
      onError('Polkadot provider not available')
      return
    }

    const requestFn = providerObj.request
    if (typeof requestFn !== 'function') {
      onError('request method is not available on Polkadot provider')
      return
    }

    setLoading(true)
    try {
      let params: unknown[] = []
      try {
        params = JSON.parse(paramsJson)
        if (!Array.isArray(params)) {
          throw new Error('Params must be an array')
        }
      } catch {
        throw new Error('Invalid JSON format for params')
      }

      const result = await (requestFn as (payload: { method: string; params?: unknown[] }) => Promise<unknown>)({
        method,
        params: params.length > 0 ? params : undefined,
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
          Request Method <span className="text-red-500">*</span>
        </label>
        <input
          type="text"
          value={method}
          onChange={(e) => setMethod(e.target.value)}
          placeholder="get_accounts"
          className="w-full px-3 py-2 text-xs font-mono border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
        />
      </div>
      <div>
        <label className="block text-xs font-medium text-gray-700 mb-1">
          Params (JSON Array)
        </label>
        <textarea
          value={paramsJson}
          onChange={(e) => setParamsJson(e.target.value)}
          placeholder="[]"
          className="w-full px-3 py-2 text-xs font-mono border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 resize-y min-h-[60px]"
          rows={3}
        />
      </div>
      <button
        onClick={handleExecute}
        disabled={loading || !method.trim()}
        className="w-full px-4 py-2 text-sm bg-blue-600 text-white rounded hover:bg-blue-700 disabled:bg-gray-400 disabled:cursor-not-allowed transition-colors"
      >
        {loading ? 'Executing...' : 'Execute Request'}
      </button>
    </div>
  )
}
