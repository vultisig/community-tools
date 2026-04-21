import { useState } from 'react'
import type { MethodComponentProps } from './types'
import {
  decodeCardanoValue,
  formatCip30Error,
  formatLovelace,
  getEnabledApi,
} from './cardanoUtils'
import { fromHex } from './cbor'

export function GetBalanceMethod({ provider, onResult, onError }: MethodComponentProps) {
  const [loading, setLoading] = useState(false)

  const handleClick = async () => {
    setLoading(true)
    try {
      const api = await getEnabledApi(provider)
      const cborHex = await api.getBalance()
      const decoded = decodeCardanoValue(fromHex(cborHex))
      onResult({
        raw: cborHex,
        lovelace: decoded.lovelace,
        formatted: formatLovelace(BigInt(decoded.lovelace)),
        assets: decoded.assets,
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
        Returns hex-encoded CBOR `Value` (lovelace + native assets). Decoded below for readability.
      </p>
      <button
        onClick={handleClick}
        disabled={loading}
        className="w-full px-4 py-2 text-sm bg-blue-600 text-white rounded hover:bg-blue-700 disabled:bg-gray-400 disabled:cursor-not-allowed transition-colors"
      >
        {loading ? 'Fetching…' : 'Call getBalance()'}
      </button>
    </div>
  )
}
