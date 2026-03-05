import { useEffect, useState } from 'react'

interface GenericMethodProps {
  provider: unknown
  methodName: string
  onResult: (result: unknown) => void
  onError: (error: string) => void
  onAccountUpdate?: (accounts: string[]) => void
}

const accountMethods = new Set(['get_accounts', 'request_accounts', 'getAccounts', 'requestAccounts', 'accounts'])

const methodArgPresets: Record<string, string> = {
  signPayload: JSON.stringify([
    {
      address: '5F3sa2TJAWMqDhXG6jhV4N8ko9q6f2f8sXXmJQq5t8R5x7Kp',
      blockHash: '0x0000000000000000000000000000000000000000000000000000000000000000',
      blockNumber: '0x00000000',
      era: '0x00',
      genesisHash: '0x0000000000000000000000000000000000000000000000000000000000000000',
      method: '0x',
      nonce: '0x00000000',
      specVersion: '0x00000000',
      tip: '0x000000000000000000',
      transactionVersion: '0x00000000',
      signedExtensions: ['CheckNonZeroSender', 'CheckSpecVersion', 'CheckTxVersion', 'CheckGenesis', 'CheckMortality', 'CheckNonce', 'CheckWeight', 'ChargeTransactionPayment'],
      version: 4,
    },
  ], null, 2),
  signpayload: JSON.stringify([
    {
      address: '5F3sa2TJAWMqDhXG6jhV4N8ko9q6f2f8sXXmJQq5t8R5x7Kp',
      blockHash: '0x0000000000000000000000000000000000000000000000000000000000000000',
      blockNumber: '0x00000000',
      era: '0x00',
      genesisHash: '0x0000000000000000000000000000000000000000000000000000000000000000',
      method: '0x',
      nonce: '0x00000000',
      specVersion: '0x00000000',
      tip: '0x000000000000000000',
      transactionVersion: '0x00000000',
      signedExtensions: ['CheckNonZeroSender', 'CheckSpecVersion', 'CheckTxVersion', 'CheckGenesis', 'CheckMortality', 'CheckNonce', 'CheckWeight', 'ChargeTransactionPayment'],
      version: 4,
    },
  ], null, 2),
  signRaw: JSON.stringify([
    {
      address: '5F3sa2TJAWMqDhXG6jhV4N8ko9q6f2f8sXXmJQq5t8R5x7Kp',
      data: '0x68656c6c6f20766f746c69736967',
      type: 'bytes',
    },
  ], null, 2),
  signraw: JSON.stringify([
    {
      address: '5F3sa2TJAWMqDhXG6jhV4N8ko9q6f2f8sXXmJQq5t8R5x7Kp',
      data: '0x68656c6c6f20766f746c69736967',
      type: 'bytes',
    },
  ], null, 2),
  signRow: JSON.stringify([
    {
      address: '5F3sa2TJAWMqDhXG6jhV4N8ko9q6f2f8sXXmJQq5t8R5x7Kp',
      data: '0x68656c6c6f20766f746c69736967',
      type: 'bytes',
    },
  ], null, 2),
  signrow: JSON.stringify([
    {
      address: '5F3sa2TJAWMqDhXG6jhV4N8ko9q6f2f8sXXmJQq5t8R5x7Kp',
      data: '0x68656c6c6f20766f746c69736967',
      type: 'bytes',
    },
  ], null, 2),
}

export function GenericMethod({ provider, methodName, onResult, onError, onAccountUpdate }: GenericMethodProps) {
  const [argsJson, setArgsJson] = useState<string>(methodArgPresets[methodName] || '[]')
  const [loading, setLoading] = useState<boolean>(false)

  useEffect(() => {
    setArgsJson(methodArgPresets[methodName] || '[]')
  }, [methodName])

  const handleExecute = async (): Promise<void> => {
    const providerObj = provider as Record<string, unknown> | null
    if (!providerObj) {
      onError('Polkadot provider not available')
      return
    }

    setLoading(true)
    try {
      let args: unknown[] = []
      try {
        args = JSON.parse(argsJson)
        if (!Array.isArray(args)) {
          throw new Error('Args must be an array')
        }
      } catch {
        throw new Error('Invalid JSON format for args')
      }

      const candidate = providerObj[methodName]
      let result: unknown

      if (typeof candidate === 'function') {
        result = await (candidate as (...methodArgs: unknown[]) => unknown)(...args)
      } else {
        result = candidate
      }

      onResult(result)

      if (onAccountUpdate && accountMethods.has(methodName)) {
        const accounts = result as string[]
        if (Array.isArray(accounts)) {
          onAccountUpdate(accounts)
        }
      }
    } catch (err) {
      onError((err as Error).message || 'Unknown error')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="space-y-3">
      <div>
        <label className="block text-xs font-medium text-gray-700 mb-1">
          Method
        </label>
        <input
          type="text"
          value={methodName}
          disabled
          className="w-full px-3 py-2 text-xs font-mono border border-gray-300 rounded-md bg-gray-50 text-gray-700"
        />
      </div>
      <div>
        <label className="block text-xs font-medium text-gray-700 mb-1">
          Args (JSON Array)
        </label>
        <textarea
          value={argsJson}
          onChange={(e) => setArgsJson(e.target.value)}
          placeholder="[]"
          className="w-full px-3 py-2 text-xs font-mono border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 resize-y min-h-[60px]"
          rows={3}
        />
      </div>
      <button
        onClick={handleExecute}
        disabled={loading}
        className="w-full px-4 py-2 text-sm bg-blue-600 text-white rounded hover:bg-blue-700 disabled:bg-gray-400 disabled:cursor-not-allowed transition-colors"
      >
        {loading ? 'Executing...' : 'Execute Method'}
      </button>
    </div>
  )
}
