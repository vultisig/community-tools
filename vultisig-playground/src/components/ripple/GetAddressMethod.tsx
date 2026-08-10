import { useState } from 'react'
import type { RippleProvider } from './types'

interface GetAddressMethodProps {
  provider: unknown
  onResult: (result: unknown) => void
  onError: (error: string) => void
  onAccountUpdate?: (accounts: string[]) => void
}

export function GetAddressMethod({ provider, onResult, onError }: GetAddressMethodProps) {
  const [loading, setLoading] = useState<boolean>(false)
  const [includePublicKey, setIncludePublicKey] = useState<boolean>(false)

  const handleGetAddress = async (): Promise<void> => {
    const xrpl = provider as Partial<RippleProvider> | null

    if (!xrpl?.getAddress || typeof xrpl.getAddress !== 'function') {
      onError('XRPL provider or getAddress method not available')
      return
    }

    setLoading(true)
    try {
      const address = await xrpl.getAddress()
      if (includePublicKey) {
        if (!xrpl.getPublicKey || typeof xrpl.getPublicKey !== 'function') {
          onError('getPublicKey method not available')
          return
        }
        const publicKey = await xrpl.getPublicKey()
        onResult({ ...address, ...publicKey })
      } else {
        onResult(address)
      }
    } catch (err) {
      onError((err as Error).message || 'Unknown error')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="space-y-4">
      <p className="text-xs text-gray-600">
        Returns the connected XRPL address via <code className="bg-gray-100 px-1 rounded">getAddress</code>.
        Optionally also fetches the public key via <code className="bg-gray-100 px-1 rounded">getPublicKey</code>.
      </p>
      <label className="flex items-center gap-2 text-xs text-gray-700">
        <input
          type="checkbox"
          checked={includePublicKey}
          onChange={(e) => setIncludePublicKey(e.target.checked)}
          className="rounded border-gray-300 focus:ring-2 focus:ring-blue-500"
        />
        Also fetch public key
      </label>
      <button
        onClick={handleGetAddress}
        disabled={loading}
        className="w-full px-4 py-2 text-sm bg-blue-600 text-white rounded hover:bg-blue-700 disabled:bg-gray-400 disabled:cursor-not-allowed transition-colors"
      >
        {loading ? 'Fetching...' : 'Get address'}
      </button>
    </div>
  )
}
