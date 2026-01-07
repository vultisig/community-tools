import { useState } from 'react'
import type { SolanaWalletProvider } from './types'

interface RequestMethodProps {
  provider: unknown
  onResult: (result: unknown) => void
  onError: (error: string) => void
  onAccountUpdate?: (accounts: string[]) => void
}

export function RequestMethod({ onResult, onError }: RequestMethodProps) {
  const [method, setMethod] = useState<string>('connect')
  const [paramsJson, setParamsJson] = useState<string>('[]')
  const [loading, setLoading] = useState<boolean>(false)

  const handleExecute = async (): Promise<void> => {
    const solanaProvider = window.vultisig?.solana as SolanaWalletProvider | undefined
    if (!solanaProvider) {
      onError('Solana provider not available')
      return
    }

    setLoading(true)
    try {
      if (!solanaProvider.request || typeof solanaProvider.request !== 'function') {
        throw new Error('request method is not available')
      }

      let params: unknown[] = []
      try {
        params = JSON.parse(paramsJson)
        if (!Array.isArray(params)) {
          throw new Error('Params must be an array')
        }
      } catch (e) {
        throw new Error('Invalid JSON format for params')
      }

      const result = await solanaProvider.request({
        method,
        params: params.length > 0 ? params : undefined,
      })

      onResult(result)
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
          Method <span className="text-red-500">*</span>
        </label>
        <input
          type="text"
          value={method}
          onChange={(e) => setMethod(e.target.value)}
          placeholder="connect"
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
          placeholder='[]'
          className="w-full px-3 py-2 text-xs font-mono border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 resize-y min-h-[60px]"
          rows={3}
        />
        <p className="text-xs text-gray-500 mt-1">
          JSON array with parameters for the request method
        </p>
      </div>
      <button
        onClick={handleExecute}
        disabled={loading || !method.trim()}
        className="w-full px-4 py-2 text-sm bg-blue-600 text-white rounded hover:bg-blue-700 disabled:bg-gray-400 disabled:cursor-not-allowed transition-colors"
      >
        {loading ? 'Requesting...' : 'Send Request'}
      </button>
    </div>
  )
}

