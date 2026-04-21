import { useState } from 'react'
import type { MethodComponentProps } from './types'
import { formatCip30Error, getEnabledApi } from './cardanoUtils'
import { fromHex, toHex } from './cbor'

export function SignDataMethod({ provider, onResult, onError }: MethodComponentProps) {
  const [addressHex, setAddressHex] = useState('')
  const [payloadMode, setPayloadMode] = useState<'utf8' | 'hex'>('utf8')
  const [payload, setPayload] = useState('')
  const [loadingAddress, setLoadingAddress] = useState(false)
  const [loading, setLoading] = useState(false)

  const prefillAddress = async () => {
    setLoadingAddress(true)
    try {
      const api = await getEnabledApi(provider)
      const addr = await api.getChangeAddress()
      setAddressHex(addr)
    } catch (err) {
      onError(formatCip30Error(err))
    } finally {
      setLoadingAddress(false)
    }
  }

  const fillSample = () => {
    setPayloadMode('utf8')
    setPayload('Hello from Vultisig Playground')
  }

  const handleSign = async () => {
    if (!addressHex.trim()) {
      onError('Address (hex) is required. Click "Use connected address" to auto-fill.')
      return
    }
    if (!payload.trim()) {
      onError('Payload is required.')
      return
    }
    setLoading(true)
    try {
      const api = await getEnabledApi(provider)
      const payloadHex =
        payloadMode === 'hex'
          ? payload.trim().replace(/^0x/i, '')
          : toHex(new TextEncoder().encode(payload))

      // Validate that hex inputs round-trip cleanly.
      if (payloadMode === 'hex') fromHex(payloadHex)

      const result = await api.signData(addressHex.trim(), payloadHex)
      onResult({
        signedAddressHex: addressHex.trim(),
        payloadHex,
        signature: result.signature,
        key: result.key,
        note: 'signature = COSE_Sign1 hex; key = COSE_Key hex',
      })
    } catch (err) {
      onError(formatCip30Error(err))
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="space-y-3">
      <p className="text-xs text-gray-600">
        Signs a payload with CIP-30 signData (COSE_Sign1 over the connected account's spending key).
      </p>

      <div>
        <div className="flex items-center justify-between mb-1">
          <label className="block text-xs font-medium text-gray-700">
            Address (hex) <span className="text-red-500">*</span>
          </label>
          <button
            onClick={prefillAddress}
            disabled={loadingAddress}
            className="text-xs text-blue-600 hover:text-blue-800 disabled:text-gray-400"
          >
            {loadingAddress ? 'Loading…' : 'Use connected address'}
          </button>
        </div>
        <input
          type="text"
          value={addressHex}
          onChange={(e) => setAddressHex(e.target.value)}
          placeholder="hex of raw address bytes (must match connected account)"
          className="w-full px-3 py-2 text-xs font-mono border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
        />
      </div>

      <div>
        <label className="block text-xs font-medium text-gray-700 mb-1">Payload Encoding</label>
        <div className="flex gap-2">
          {(['utf8', 'hex'] as const).map((m) => (
            <button
              key={m}
              onClick={() => setPayloadMode(m)}
              className={`px-3 py-1.5 text-xs rounded border transition-colors ${
                payloadMode === m
                  ? 'bg-blue-600 text-white border-blue-600'
                  : 'bg-white text-gray-700 border-gray-300 hover:bg-gray-50'
              }`}
            >
              {m === 'utf8' ? 'UTF-8 text' : 'Hex bytes'}
            </button>
          ))}
          <button
            onClick={fillSample}
            className="ml-auto px-2 py-1.5 text-xs bg-gray-100 border border-gray-300 text-gray-700 rounded hover:bg-gray-200 transition-colors"
          >
            Load sample
          </button>
        </div>
      </div>

      <div>
        <label className="block text-xs font-medium text-gray-700 mb-1">
          Payload <span className="text-red-500">*</span>
        </label>
        <textarea
          value={payload}
          onChange={(e) => setPayload(e.target.value)}
          placeholder={payloadMode === 'utf8' ? 'Hello, Cardano!' : 'a1b2c3…'}
          className="w-full px-3 py-2 text-xs font-mono border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 resize-y"
          rows={3}
        />
      </div>

      <button
        onClick={handleSign}
        disabled={loading}
        className="w-full px-4 py-2 text-sm bg-blue-600 text-white rounded hover:bg-blue-700 disabled:bg-gray-400 disabled:cursor-not-allowed transition-colors"
      >
        {loading ? 'Signing…' : 'Call signData()'}
      </button>
    </div>
  )
}
