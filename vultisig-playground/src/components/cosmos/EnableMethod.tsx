import { useState, useCallback } from 'react'
import { enableCosmosChain, fetchCosmosAccountInfo } from './cosmosUtils'

interface EnableMethodProps {
  provider: unknown
  onResult: (result: unknown) => void
  onError: (error: string) => void
  onAccountUpdate?: (accounts: string[]) => void
}

const COSMOS_CHAIN_IDS = [
  { value: 'cosmoshub-4', label: 'Cosmos Hub (cosmoshub-4)' },
  { value: 'thorchain-1', label: 'THORChain (thorchain-1)' },
]

export function EnableMethod({ onResult, onError, onAccountUpdate }: EnableMethodProps) {
  const [chainId, setChainId] = useState<string>('cosmoshub-4')
  const [loading, setLoading] = useState<boolean>(false)

  const handleEnable = useCallback(async (): Promise<void> => {
    const keplrProvider = window.vultisig?.keplr
    if (!keplrProvider) {
      onError('Keplr provider not available')
      return
    }

    setLoading(true)

    try {
      await enableCosmosChain(keplrProvider, chainId)
      
      // After enabling, fetch account info
      const info = await fetchCosmosAccountInfo(keplrProvider, chainId)
      
      if (onAccountUpdate && info.address) {
        onAccountUpdate([info.address])
      }

      onResult({
        chainId,
        enabled: true,
        accountInfo: info,
        provider: 'vultisig',
      })
    } catch (err) {
      onError((err as Error).message || 'Unknown error')
    } finally {
      setLoading(false)
    }
  }, [chainId, onResult, onError, onAccountUpdate])

  return (
    <div className="space-y-4">
      <div>
        <label className="block text-xs font-medium text-gray-700 mb-1">
          Chain ID <span className="text-red-500">*</span>
        </label>
        <select
          value={chainId}
          onChange={(e) => {
            setChainId(e.target.value)
            onResult(undefined)
          }}
          className="w-full px-3 py-2 text-xs font-mono border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 bg-white"
        >
          {COSMOS_CHAIN_IDS.map((chain) => (
            <option key={chain.value} value={chain.value}>
              {chain.label}
            </option>
          ))}
        </select>
      </div>

      <div className="space-y-3">
        <button
          onClick={handleEnable}
          disabled={loading}
          className="w-full px-4 py-2 text-sm bg-blue-600 text-white rounded hover:bg-blue-700 disabled:bg-gray-400 disabled:cursor-not-allowed transition-colors"
        >
          {loading ? 'Enabling...' : 'Enable'}
        </button>
      </div>
    </div>
  )
}

