import { useState } from 'react'
import type { TonConnectBridge } from './types'

interface SendTransactionMethodProps {
  provider: unknown
  onResult: (result: unknown) => void
  onError: (error: string) => void
  onAccountUpdate?: (accounts: string[]) => void
}

interface TonMessage {
  address: string
  amount: string
  payload: string
}

const getDefaultValidUntil = () => String(Math.floor(Date.now() / 1000) + 300)

export function SendTransactionMethod({ provider, onResult, onError }: SendTransactionMethodProps) {
  const [messages, setMessages] = useState<TonMessage[]>([
    { address: '', amount: '', payload: '' },
  ])
  const [validUntil, setValidUntil] = useState<string>(getDefaultValidUntil)
  const [network] = useState<string>('-239')
  const [loading, setLoading] = useState(false)

  const addMessage = () => {
    if (messages.length < 4) {
      setMessages([...messages, { address: '', amount: '', payload: '' }])
    }
  }

  const removeMessage = (index: number) => {
    if (messages.length > 1) {
      setMessages(messages.filter((_, i) => i !== index))
    }
  }

  const updateMessage = (index: number, field: keyof TonMessage, value: string) => {
    setMessages(messages.map((msg, i) => (i === index ? { ...msg, [field]: value } : msg)))
  }

  const loadExample = () => {
    setMessages([{ address: '', amount: '0.001', payload: '' }])
    setValidUntil(getDefaultValidUntil())
  }

  const handleSendTransaction = async () => {
    const bridge = provider as TonConnectBridge
    if (!bridge?.send || typeof bridge.send !== 'function') {
      onError('TonConnect bridge or send method not available')
      return
    }

    for (let i = 0; i < messages.length; i++) {
      const msg = messages[i]
      if (!msg.address.trim()) {
        onError(`Message ${i + 1}: recipient address is required`)
        return
      }
      const amount = parseFloat(msg.amount)
      if (isNaN(amount) || amount <= 0) {
        onError(`Message ${i + 1}: amount must be a positive number`)
        return
      }
    }

    const validUntilNum = parseInt(validUntil, 10)
    if (isNaN(validUntilNum) || validUntilNum <= Math.floor(Date.now() / 1000)) {
      onError('Valid until must be a future Unix timestamp')
      return
    }

    const txPayload = {
      valid_until: validUntilNum,
      network,
      messages: messages.map((msg) => ({
        address: msg.address.trim(),
        amount: Math.round(parseFloat(msg.amount) * 1e9).toString(),
        ...(msg.payload.trim() ? { payload: msg.payload.trim() } : {}),
      })),
    }

    setLoading(true)
    try {
      const result = await bridge.send({
        method: 'sendTransaction',
        params: [JSON.stringify(txPayload)],
        id: Date.now().toString(),
      })
      onResult(result)
    } catch (err) {
      onError((err as Error).message || 'Unknown error')
    } finally {
      setLoading(false)
    }
  }

  const canSubmit =
    !loading && messages.every((msg) => msg.address.trim() && msg.amount.trim())

  return (
    <div className="space-y-3">
      <p className="text-xs text-gray-600">
        Send a transaction using TonConnect. Constructs a message payload and sends it to the wallet
        for signing. Returns a signed BOC (Bag of Cells) on success.
      </p>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
        <div>
          <label className="block text-xs font-medium text-gray-700 mb-1">
            Valid Until (Unix timestamp)
          </label>
          <div className="flex gap-2">
            <input
              type="text"
              value={validUntil}
              onChange={(e) => setValidUntil(e.target.value)}
              className="flex-1 px-3 py-2 text-xs font-mono border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
            />
            <button
              onClick={() => setValidUntil(getDefaultValidUntil())}
              className="px-3 py-2 text-xs bg-gray-100 border border-gray-300 text-gray-700 rounded hover:bg-gray-200 transition-colors whitespace-nowrap"
            >
              Refresh
            </button>
          </div>
          <p className="text-xs text-gray-500 mt-1">Default: 5 minutes from now.</p>
        </div>

        <div>
          <label className="block text-xs font-medium text-gray-700 mb-1">Network</label>
          <input
            type="text"
            value={network}
            readOnly
            className="w-full px-3 py-2 text-xs font-mono border border-gray-300 rounded-md bg-gray-50 text-gray-500 cursor-not-allowed"
          />
          <p className="text-xs text-gray-500 mt-1">-239 = mainnet (only supported network).</p>
        </div>
      </div>

      <div>
        <div className="flex items-center justify-between mb-2">
          <label className="block text-xs font-medium text-gray-700">
            Messages ({messages.length}/4)
          </label>
          <div className="flex gap-2">
            <button
              onClick={loadExample}
              className="px-2 py-1 text-xs bg-gray-100 border border-gray-300 text-gray-700 rounded hover:bg-gray-200 transition-colors"
            >
              Load Example
            </button>
            <button
              onClick={addMessage}
              disabled={messages.length >= 4}
              className="px-2 py-1 text-xs bg-blue-600 text-white rounded hover:bg-blue-700 disabled:bg-gray-400 disabled:cursor-not-allowed transition-colors"
            >
              + Add Message
            </button>
          </div>
        </div>

        <div className="space-y-3">
          {messages.map((msg, index) => (
            <div key={index} className="border border-gray-200 rounded-md p-3 space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-xs font-medium text-gray-600">Message {index + 1}</span>
                <button
                  onClick={() => removeMessage(index)}
                  disabled={messages.length <= 1}
                  className="text-xs text-red-500 hover:text-red-700 disabled:text-gray-400 disabled:cursor-not-allowed transition-colors"
                >
                  Remove
                </button>
              </div>

              <div>
                <label className="block text-xs font-medium text-gray-700 mb-1">
                  Recipient Address <span className="text-red-500">*</span>
                </label>
                <input
                  type="text"
                  value={msg.address}
                  onChange={(e) => updateMessage(index, 'address', e.target.value)}
                  placeholder="TON address (e.g., UQ... or EQ...)"
                  className="w-full px-3 py-2 text-xs font-mono border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                />
              </div>

              <div>
                <label className="block text-xs font-medium text-gray-700 mb-1">
                  Amount (TON) <span className="text-red-500">*</span>
                </label>
                <input
                  type="text"
                  value={msg.amount}
                  onChange={(e) => updateMessage(index, 'amount', e.target.value)}
                  placeholder="e.g., 0.1"
                  className="w-full px-3 py-2 text-xs font-mono border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                />
                <p className="text-xs text-gray-500 mt-1">Will be converted to nanotons.</p>
              </div>

              <div>
                <label className="block text-xs font-medium text-gray-700 mb-1">
                  Payload (optional)
                </label>
                <input
                  type="text"
                  value={msg.payload}
                  onChange={(e) => updateMessage(index, 'payload', e.target.value)}
                  placeholder="Base64-encoded BOC message body"
                  className="w-full px-3 py-2 text-xs font-mono border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                />
                <p className="text-xs text-gray-500 mt-1">
                  Optional message body. Leave empty for simple transfers.
                </p>
              </div>
            </div>
          ))}
        </div>
      </div>

      <button
        onClick={handleSendTransaction}
        disabled={!canSubmit}
        className="w-full px-4 py-2 text-sm bg-blue-600 text-white rounded hover:bg-blue-700 disabled:bg-gray-400 disabled:cursor-not-allowed transition-colors"
      >
        {loading ? 'Sending...' : 'Send Transaction'}
      </button>
    </div>
  )
}
