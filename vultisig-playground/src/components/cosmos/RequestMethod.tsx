import { useMemo, useState } from 'react'

interface RequestMethodProps {
  provider: unknown
  onResult: (result: unknown) => void
  onError: (error: string) => void
  onAccountUpdate?: (accounts: string[]) => void
}

type CosmosRequestArgs = {
  method: string
  params?: unknown[]
}

type ActionId = 'get_accounts' | 'request_accounts' | 'wallet_switch_chain'

const COSMOS_CHAIN_IDS = [
  { value: 'cosmoshub-4', label: 'Cosmos Hub (cosmoshub-4)' },
  { value: 'osmosis-1', label: 'Osmosis (osmosis-1)' },
  { value: 'kaiyo-1', label: 'Kujira (kaiyo-1)' },
  { value: 'dydx-1', label: 'DyDx (dydx-1)' },
] as const

const ACTIONS: Array<{ id: ActionId; label: string; description: string }> = [
  { id: 'get_accounts', label: 'get_accounts', description: 'Get currently connected accounts' },
  { id: 'request_accounts', label: 'request_accounts', description: 'Request user to connect accounts' },
  { id: 'wallet_switch_chain', label: 'wallet_switch_chain', description: 'Switch active chain (params: [{ chainId }])' },
]

export function RequestMethod({ provider, onResult, onError, onAccountUpdate }: RequestMethodProps) {
  const [action, setAction] = useState<ActionId>('get_accounts')
  const [chainId, setChainId] = useState<string>('cosmoshub-4')
  const [paramsJson, setParamsJson] = useState<string>('[]')
  const [loading, setLoading] = useState<boolean>(false)

  const needsChainId = action === 'wallet_switch_chain'
  const needsParamsJson = !needsChainId && action !== 'get_accounts' && action !== 'request_accounts'

  const requestArgs: CosmosRequestArgs = useMemo(() => {
    if (needsChainId) {
      return { method: action, params: [{ chainId }] }
    }
    if (action === 'get_accounts' || action === 'request_accounts') {
      return { method: action }
    }

    try {
      const parsed = JSON.parse(paramsJson)
      const params = Array.isArray(parsed) ? parsed : []
      return { method: action, params }
    } catch {
      return { method: action, params: [] }
    }
  }, [action, chainId, needsChainId, paramsJson])

  const handleExecute = async (): Promise<void> => {
    const cosmosProvider = provider as { request?: (args: CosmosRequestArgs) => Promise<unknown> } | null
    if (!cosmosProvider) {
      onError('Cosmos provider not available')
      return
    }
    if (!cosmosProvider.request || typeof cosmosProvider.request !== 'function') {
      onError('request method is not available')
      return
    }

    setLoading(true)
    try {
      const result = await cosmosProvider.request(requestArgs)
      onResult(result)

      if ((action === 'get_accounts' || action === 'request_accounts') && onAccountUpdate) {
        const accounts = result as unknown
        if (Array.isArray(accounts)) {
          onAccountUpdate(accounts.map((a) => String(a)))
        }
      }
    } catch (err) {
      console.error(err)
      onError((err as Error).message || 'Unknown error')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="space-y-3">
      <div>
        <label className="block text-xs font-medium text-gray-700 mb-1">Action</label>
        <select
          value={action}
          onChange={(e) => {
            setAction(e.target.value as ActionId)
            onResult(undefined)
          }}
          className="w-full px-3 py-2 text-xs font-mono border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 bg-white"
        >
          {ACTIONS.map((a) => (
            <option key={a.id} value={a.id}>
              {a.label} - {a.description}
            </option>
          ))}
        </select>
      </div>

      {needsChainId && (
        <div>
          <label className="block text-xs font-medium text-gray-700 mb-1">
            Chain ID <span className="text-red-500">*</span>
          </label>
          <select
            value={chainId}
            onChange={(e) => setChainId(e.target.value)}
            className="w-full px-3 py-2 text-xs font-mono border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 bg-white"
          >
            {COSMOS_CHAIN_IDS.map((c) => (
              <option key={c.value} value={c.value}>
                {c.label}
              </option>
            ))}
          </select>
        </div>
      )}

      {needsParamsJson && (
        <div>
          <label className="block text-xs font-medium text-gray-700 mb-1">Params (JSON array)</label>
          <textarea
            value={paramsJson}
            onChange={(e) => setParamsJson(e.target.value)}
            placeholder="[]"
            className="w-full px-3 py-2 text-xs font-mono border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 resize-y min-h-[60px]"
            rows={3}
          />
        </div>
      )}

      <button
        onClick={handleExecute}
        disabled={loading}
        className="w-full px-4 py-2 text-sm bg-blue-600 text-white rounded hover:bg-blue-700 disabled:bg-gray-400 disabled:cursor-not-allowed transition-colors"
      >
        {loading ? 'Executing...' : 'Execute Request'}
      </button>
    </div>
  )
}

