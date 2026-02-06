import { useState } from 'react'

interface EthSendTransactionMethodProps {
  provider: unknown
  onResult: (result: unknown) => void
  onError: (error: string) => void
  onAccountUpdate?: (accounts: string[]) => void
}

export function EthSendTransactionMethod({ provider, onResult, onError }: EthSendTransactionMethodProps) {
  const [from, setFrom] = useState<string>('')
  const [to, setTo] = useState<string>('')
  const [value, setValue] = useState<string>('0x0')
  const [data, setData] = useState<string>('0x')
  const [gas, setGas] = useState<string>('')
  const [loading, setLoading] = useState<boolean>(false)

  const handleSend = async (): Promise<void> => {
    const ethProvider = provider as {
      request?: (args: { method: string; params?: unknown[] }) => Promise<unknown>
    } | null

    if (!ethProvider?.request || typeof ethProvider.request !== 'function') {
      onError('Ethereum provider or request method not available')
      return
    }

    if (!from.trim()) {
      onError('From address is required')
      return
    }

    const txDetails: Record<string, string> = {
      from: from.trim(),
    }
    if (to.trim()) txDetails.to = to.trim()
    if (value.trim()) txDetails.value = value.trim()
    if (data.trim()) txDetails.data = data.trim()
    if (gas.trim()) txDetails.gas = gas.trim()

    setLoading(true)
    try {
      const transactionHash = await ethProvider.request({
        method: 'eth_sendTransaction',
        params: [txDetails],
      })
      onResult(transactionHash)
    } catch (err) {
      onError((err as Error).message || 'Unknown error')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="space-y-4">
      <p className="text-xs text-gray-600">
        Sends a transaction via <code className="bg-gray-100 px-1 rounded">eth_sendTransaction</code>. Returns the transaction hash.
      </p>
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
        <label className="block text-xs font-medium text-gray-700 mb-1">Value (hex)</label>
        <input
          type="text"
          value={value}
          onChange={(e) => setValue(e.target.value)}
          placeholder="0x0"
          className="w-full px-3 py-2 text-xs font-mono border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
        />
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
      <div>
        <label className="block text-xs font-medium text-gray-700 mb-1">Gas (hex, optional)</label>
        <input
          type="text"
          value={gas}
          onChange={(e) => setGas(e.target.value)}
          placeholder="e.g. 0x5208"
          className="w-full px-3 py-2 text-xs font-mono border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
        />
      </div>
      <button
        onClick={handleSend}
        disabled={loading || !from.trim()}
        className="w-full px-4 py-2 text-sm bg-blue-600 text-white rounded hover:bg-blue-700 disabled:bg-gray-400 disabled:cursor-not-allowed transition-colors"
      >
        {loading ? 'Sending...' : 'Send transaction'}
      </button>
    </div>
  )
}
