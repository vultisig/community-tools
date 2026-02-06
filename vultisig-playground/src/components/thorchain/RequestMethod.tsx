import { useState } from 'react'

interface RequestMethodProps {
  provider: unknown
  onResult: (result: unknown) => void
  onError: (error: string) => void
  onAccountUpdate?: (accounts: string[]) => void
}

type ActionId = 'get_accounts' | 'request_accounts' | 'send_transaction' | 'deposit_transaction'

const ACTIONS: Array<{ id: ActionId; label: string; description: string }> = [
  { id: 'get_accounts', label: 'get_accounts', description: 'Get currently connected accounts' },
  { id: 'request_accounts', label: 'request_accounts', description: 'Request user to connect accounts' },
  { id: 'send_transaction', label: 'send_transaction', description: 'Send transaction (transfer)' },
  { id: 'deposit_transaction', label: 'deposit_transaction', description: 'Deposit transaction (e.g. bond, unbond)' },
]

const ACCOUNT_ACTIONS: ActionId[] = ['get_accounts', 'request_accounts']

const DEFAULT_TICKER = 'RUNE'
const DEFAULT_DECIMALS = 8

export function RequestMethod({ provider, onResult, onError, onAccountUpdate }: RequestMethodProps) {
  const [action, setAction] = useState<ActionId>('get_accounts')
  const [from, setFrom] = useState<string>('')
  const [to, setTo] = useState<string>('')
  const [ticker, setTicker] = useState<string>(DEFAULT_TICKER)
  const [amountStr, setAmountStr] = useState<string>('')
  const [memo, setMemo] = useState<string>('')
  const [loading, setLoading] = useState<boolean>(false)

  const needsTxForm = !ACCOUNT_ACTIONS.includes(action)

  const handleExecute = async (): Promise<void> => {
    const thorProvider = provider as {
      request?: (args: { method: string; params?: unknown[] }) => Promise<unknown>
    } | null

    if (!thorProvider?.request || typeof thorProvider.request !== 'function') {
      onError('THORChain provider or request method not available')
      return
    }

    if (needsTxForm) {
      if (!from.trim()) {
        onError('From address is required')
        return
      }
      if (action === 'send_transaction' && !to.trim()) {
        onError('To address is required')
        return
      }
    }

    const buildTxDetails = (): Record<string, unknown> => {
      const details: Record<string, unknown> = {
        asset: { ticker: ticker.trim() || DEFAULT_TICKER },
        from: from.trim(),
      }
      if (action === 'send_transaction' && to.trim()) details.to = to.trim()
      const amt = amountStr.trim()
      if (amt) details.amount = { amount: amt, decimals: DEFAULT_DECIMALS }
      if (memo.trim()) details.memo = memo.trim()
      return details
    }

    const requestPayload = needsTxForm
      ? { method: action, params: [buildTxDetails()] }
      : { method: action }

    setLoading(true)
    try {
      const result = await thorProvider.request(requestPayload)
      onResult(result)
      if (ACCOUNT_ACTIONS.includes(action) && onAccountUpdate) {
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

  const canExecute = !needsTxForm || (action === 'deposit_transaction' ? from.trim() : from.trim() && to.trim())

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

      {needsTxForm && (
        <>
          <div>
            <label className="block text-xs font-medium text-gray-700 mb-1">
              From <span className="text-red-500">*</span>
            </label>
            <input
              type="text"
              value={from}
              onChange={(e) => setFrom(e.target.value)}
              placeholder="thor1..."
              className="w-full px-3 py-2 text-xs font-mono border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
            />
          </div>
          <div>
            <label className="block text-xs font-medium text-gray-700 mb-1">Asset ticker</label>
            <input
              type="text"
              value={ticker}
              onChange={(e) => setTicker(e.target.value)}
              placeholder="RUNE"
              className="w-full px-3 py-2 text-xs font-mono border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
            />
          </div>
          {action === 'send_transaction' && (
            <div>
              <label className="block text-xs font-medium text-gray-700 mb-1">
                To <span className="text-red-500">*</span>
              </label>
              <input
                type="text"
                value={to}
                onChange={(e) => setTo(e.target.value)}
                placeholder="thor1..."
                className="w-full px-3 py-2 text-xs font-mono border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
              />
            </div>
          )}
          <div>
            <label className="block text-xs font-medium text-gray-700 mb-1">Amount (base units)</label>
            <input
              type="text"
              value={amountStr}
              onChange={(e) => setAmountStr(e.target.value)}
              placeholder="0 (1 RUNE = 1e8 base units)"
              className="w-full px-3 py-2 text-xs font-mono border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
            />
            <p className="text-xs text-gray-500 mt-1">Sent as amount: &#123; amount, decimals: {DEFAULT_DECIMALS} &#125;</p>
          </div>
          <div>
            <label className="block text-xs font-medium text-gray-700 mb-1">Memo</label>
            <input
              type="text"
              value={memo}
              onChange={(e) => setMemo(e.target.value)}
              placeholder="Optional memo (e.g. bond, unbond)"
              className="w-full px-3 py-2 text-xs font-mono border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
            />
          </div>
        </>
      )}

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
