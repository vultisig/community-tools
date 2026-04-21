import { useState } from 'react'
import type { MethodComponentProps } from './types'
import { formatCip30Error, getEnabledApi } from './cardanoUtils'

export function SubmitTxMethod({ provider, onResult, onError }: MethodComponentProps) {
  const [txHex, setTxHex] = useState('')
  const [loading, setLoading] = useState(false)

  const handleSubmit = async () => {
    if (!txHex.trim()) {
      onError('Signed transaction CBOR hex is required')
      return
    }
    setLoading(true)
    try {
      const api = await getEnabledApi(provider)
      const txHash = await api.submitTx(txHex.trim())
      onResult({ txHash, explorer: `https://cardanoscan.io/transaction/${txHash}` })
    } catch (err) {
      onError(formatCip30Error(err))
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="space-y-3">
      <p className="text-xs text-gray-600">
        Broadcasts a fully signed transaction CBOR to the Cardano network. Returns the tx hash.
      </p>
      <div>
        <label className="block text-xs font-medium text-gray-700 mb-1">
          Signed transaction CBOR hex <span className="text-red-500">*</span>
        </label>
        <textarea
          value={txHex}
          onChange={(e) => setTxHex(e.target.value)}
          placeholder="Paste the signed tx hex produced by signTx (with body + witness set combined)"
          className="w-full px-3 py-2 text-xs font-mono border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 resize-y"
          rows={5}
        />
      </div>
      <button
        onClick={handleSubmit}
        disabled={loading || !txHex.trim()}
        className="w-full px-4 py-2 text-sm bg-blue-600 text-white rounded hover:bg-blue-700 disabled:bg-gray-400 disabled:cursor-not-allowed transition-colors"
      >
        {loading ? 'Submitting…' : 'Call submitTx()'}
      </button>
    </div>
  )
}
