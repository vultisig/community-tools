import { useState } from 'react'
import { DEFAULT_TYPED_DATA } from './SignTypedDataV4Method'

interface RequestMethodProps {
  provider: unknown
  onResult: (result: unknown) => void
  onError: (error: string) => void
  onAccountUpdate?: (accounts: string[]) => void
}

type ActionId = 'eth_accounts' | 'eth_requestAccounts' | 'eth_sendTransaction' | 'eth_signTypedData_v4'

const ACTIONS: Array<{ id: ActionId; label: string; description: string }> = [
  { id: 'eth_accounts', label: 'eth_accounts', description: 'Get connected accounts' },
  { id: 'eth_requestAccounts', label: 'eth_requestAccounts', description: 'Request user to connect accounts' },
  { id: 'eth_sendTransaction', label: 'eth_sendTransaction', description: 'Send transaction (returns tx hash)' },
  { id: 'eth_signTypedData_v4', label: 'eth_signTypedData_v4', description: 'Sign EIP-712 typed data' },
]

const ACCOUNT_ACTIONS: ActionId[] = ['eth_accounts', 'eth_requestAccounts']

// 0.0001 ETH in wei (hex for eth_sendTransaction)
const DEFAULT_VALUE_HEX = '0x5af3107a4000'

export function RequestMethod({ provider, onResult, onError, onAccountUpdate }: RequestMethodProps) {
  const [action, setAction] = useState<ActionId>('eth_accounts')
  const [from, setFrom] = useState<string>('')
  const [to, setTo] = useState<string>('')
  const [value, setValue] = useState<string>(DEFAULT_VALUE_HEX)
  const [data, setData] = useState<string>('0x')
  const [signerAddress, setSignerAddress] = useState<string>('')
  const [typedDataJson, setTypedDataJson] = useState<string>(DEFAULT_TYPED_DATA)
  const [loading, setLoading] = useState<boolean>(false)

  const isAccountAction = ACCOUNT_ACTIONS.includes(action)
  const isSendTx = action === 'eth_sendTransaction'

  const handleExecute = async (): Promise<void> => {
    const ethProvider = provider as {
      request?: (args: { method: string; params?: unknown[] }) => Promise<unknown>
    } | null

    if (!ethProvider?.request || typeof ethProvider.request !== 'function') {
      onError('Ethereum provider or request method not available')
      return
    }

    if (!isAccountAction) {
      if (isSendTx) {
        if (!from.trim()) {
          onError('From address is required')
          return
        }
      } else {
        if (!signerAddress.trim()) {
          onError('Signer address is required')
          return
        }
        if (!typedDataJson.trim()) {
          onError('Typed data (EIP-712 JSON) is required')
          return
        }
      }
    }

    const requestPayload: { method: string; params?: unknown[] } = isAccountAction
      ? { method: action }
      : isSendTx
        ? {
            method: 'eth_sendTransaction',
            params: [
              (() => {
                const tx: Record<string, string> = { from: from.trim() }
                if (to.trim()) tx.to = to.trim()
                if (value.trim()) tx.value = value.trim()
                if (data.trim()) tx.data = data.trim()
                return tx
              })(),
            ],
          }
        : {
            method: 'eth_signTypedData_v4',
            params: [signerAddress.trim(), typedDataJson.trim()],
          }

    setLoading(true)
    try {
      const result = await ethProvider.request(requestPayload)
      onResult(result)
      if (isAccountAction && onAccountUpdate) {
        const accounts = result as unknown
        if (Array.isArray(accounts)) {
          onAccountUpdate(accounts.map((a) => String(a)))
        }
      }
    } catch (err) {
      onError((err as Error).message || 'Unknown error')
    } finally {
      setLoading(false)
    }
  }

  const canExecute = isAccountAction
    ? true
    : isSendTx
      ? !!from.trim()
      : !!signerAddress.trim() && !!typedDataJson.trim()

  return (
    <div className="space-y-4">
      <p className="text-xs text-gray-600">
        All actions go through <code className="bg-gray-100 px-1 rounded">provider.request(&#123; method, params &#125;)</code>. Choose the action below.
      </p>

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
              {a.label} — {a.description}
            </option>
          ))}
        </select>
      </div>

      {!isAccountAction && isSendTx ? (
        <>
          <div>
            <label className="block text-xs font-medium text-gray-700 mb-1">
              From <span className="text-red-500">*</span>
            </label>
            <input
              type="text"
              value={from}
              onChange={(e) => setFrom(e.target.value)}
              placeholder="0x..."
              className="w-full px-3 py-2 text-xs font-mono border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
            />
          </div>
          <div>
            <label className="block text-xs font-medium text-gray-700 mb-1">To</label>
            <input
              type="text"
              value={to}
              onChange={(e) => setTo(e.target.value)}
              placeholder="0x..."
              className="w-full px-3 py-2 text-xs font-mono border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
            />
          </div>
          <div>
            <label className="block text-xs font-medium text-gray-700 mb-1">Value (hex, wei)</label>
            <input
              type="text"
              value={value}
              onChange={(e) => setValue(e.target.value)}
              placeholder={DEFAULT_VALUE_HEX}
              className="w-full px-3 py-2 text-xs font-mono border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
            />
            <p className="text-xs text-gray-500 mt-1">Default: 0.0001 ETH (0x5af3107a4000 wei)</p>
          </div>
          <div>
            <label className="block text-xs font-medium text-gray-700 mb-1">Data (hex)</label>
            <input
              type="text"
              value={data}
              onChange={(e) => setData(e.target.value)}
              placeholder="0x"
              className="w-full px-3 py-2 text-xs font-mono border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
            />
          </div>
        </>
      ) : !isAccountAction ? (
        <>
          <div>
            <label className="block text-xs font-medium text-gray-700 mb-1">
              Signer address <span className="text-red-500">*</span>
            </label>
            <input
              type="text"
              value={signerAddress}
              onChange={(e) => setSignerAddress(e.target.value)}
              placeholder="0x..."
              className="w-full px-3 py-2 text-xs font-mono border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
            />
          </div>
          <div>
            <label className="block text-xs font-medium text-gray-700 mb-1">
              EIP-712 typed data (JSON) <span className="text-red-500">*</span>
            </label>
            <textarea
              value={typedDataJson}
              onChange={(e) => setTypedDataJson(e.target.value)}
              placeholder='{"domain":{...},"primaryType":"...","types":{...},"message":{...}}'
              className="w-full px-3 py-2 text-xs font-mono border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 resize-y min-h-[320px]"
              rows={20}
              spellCheck={false}
            />
          </div>
        </>
      ) : null}

      <button
        onClick={handleExecute}
        disabled={loading || !canExecute}
        className="w-full px-4 py-2 text-sm bg-blue-600 text-white rounded hover:bg-blue-700 disabled:bg-gray-400 disabled:cursor-not-allowed transition-colors"
      >
        {loading ? 'Executing...' : `Execute ${action}`}
      </button>
    </div>
  )
}
