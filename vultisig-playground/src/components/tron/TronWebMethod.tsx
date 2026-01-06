import { useState, useCallback, useEffect } from 'react'
import {
  getTronTransactionExamples,
  getTronExampleDescriptions,
  type TronTransaction,
} from './tronExamples'

interface TronWebMethodProps {
  provider: unknown
  onResult: (result: unknown) => void
  onError: (error: string) => void
  onAccountUpdate?: (accounts: string[]) => void
}

type TronExampleType =
  | 'transferTRX'
  | 'triggerSmartContractGeneric'

const availableMethods = [
  { value: 'defaultAddress', label: 'tronWeb.defaultAddress.base58', description: 'Get default Tron address' },
  { value: 'signAndBroadcast', label: 'trx.sign + broadcast', description: 'Sign and broadcast a transaction' },
]

function TronWebMethodComponent({ onResult, onError }: TronWebMethodProps) {
  const [method, setMethod] = useState<string>('defaultAddress')
  const [selectedExample, setSelectedExample] = useState<TronExampleType | ''>('')
  const [transactionJson, setTransactionJson] = useState<string>('')
  const [fromAddress, setFromAddress] = useState<string>('')
  const [toAddress, setToAddress] = useState<string>('TB3fnJmKZ98MrXrvJthv1B4SYy2Jfm6Qtf')
  const [loading, setLoading] = useState<boolean>(false)
  const [loadingTronLink, setLoadingTronLink] = useState<boolean>(false)
  const [loadingAddress, setLoadingAddress] = useState<boolean>(false)
  const [loadingExample, setLoadingExample] = useState<boolean>(false)

  const exampleDescriptions = getTronExampleDescriptions()

  const exampleOptions: Array<{ value: TronExampleType; label: string }> = [
    { value: 'transferTRX', label: exampleDescriptions.transferTRX },
    {
      value: 'triggerSmartContractGeneric',
      label: exampleDescriptions.triggerSmartContractGeneric,
    },
  ]

  const fetchDefaultAddress = useCallback(async (): Promise<void> => {
    setLoadingAddress(true)
    try {
      if (!window.vultisig?.tron?.tronWeb?.defaultAddress?.base58) {
        throw new Error('Please use the "request" method first to connect your Tron account. defaultAddress.base58 is not available in tronWeb.')
      }

      const address = (window.vultisig.tron.tronWeb.defaultAddress as { base58: string }).base58
      setFromAddress(address)
      if (!toAddress || toAddress === 'TB3fnJmKZ98MrXrvJthv1B4SYy2Jfm6Qtf') {
        setToAddress('TB3fnJmKZ98MrXrvJthv1B4SYy2Jfm6Qtf')
      }
    } catch (err) {
      onError((err as Error).message || 'Failed to fetch address')
    } finally {
      setLoadingAddress(false)
    }
  }, [onError, toAddress])

  const handleLoadExample = useCallback(
    async (exampleType: TronExampleType): Promise<void> => {
      if (!fromAddress) {
        onError('Please fetch or enter a from address first')
        return
      }

      setLoadingExample(true)
      try {
        const example = await getTronTransactionExamples(fromAddress, toAddress, exampleType) as TronTransaction

        console.log('Example loaded:', example)
        console.log('Example raw_data:', example?.raw_data)

        if (!example || !example.raw_data) {
          console.error('Example is invalid:', { example, hasRawData: !!example?.raw_data })
          onError(`Example ${exampleType} not found or invalid`)
          return
        }

        setTransactionJson(JSON.stringify(example, null, 2))
        setSelectedExample(exampleType)
      } catch (err) {
        console.error('Error loading example:', err)
        onError((err as Error).message || 'Failed to load example')
      } finally {
        setLoadingExample(false)
      }
    },
    [fromAddress, toAddress, onError]
  )

  useEffect(() => {
    onResult(undefined)
    onError('')
  }, [method, selectedExample])

  useEffect(() => {
    setTransactionJson('')
    setSelectedExample('')
  }, [fromAddress, toAddress])

  const handleExecute = async (useTronLink: boolean = false): Promise<void> => {
    let tronWeb: Record<string, unknown> | null = null
    let tronProvider: unknown = null
    
    if (useTronLink) {
      const windowWithTron = window as unknown as {
        tronWeb?: Record<string, unknown>
        tronLink?: { tronWeb?: Record<string, unknown>; request?: (params: { method: string; params?: unknown[] }) => Promise<unknown> }
      }
      tronWeb = (windowWithTron.tronWeb || windowWithTron.tronLink?.tronWeb) || null
      tronProvider = windowWithTron.tronLink || null
      if (!tronWeb || !tronProvider) {
        onError('TronLink extension not available')
        return
      }
      setLoadingTronLink(true)
    } else {
      tronProvider = window.vultisig?.tron
      if (!tronProvider) {
        onError('Tron provider not available')
        return
      }
      if (!window.vultisig?.tron?.tronWeb) {
        onError('Please use the "request" method first to connect your Tron account. tronWeb object is not available on Tron provider.')
        return
      }
      tronWeb = window.vultisig.tron.tronWeb as Record<string, unknown>
      setLoading(true)
    }

    try {
      if (method === 'defaultAddress') {
        let defaultAddress = tronWeb.defaultAddress as { base58?: string } | undefined
        
        if (useTronLink && (!defaultAddress?.base58)) {
          const providerObj = tronProvider as { request?: (params: { method: string; params?: unknown[] }) => Promise<unknown> }
          if (providerObj.request) {
            await providerObj.request({
              method: 'tron_requestAccounts',
              params: [],
            })
            const windowWithTron = window as unknown as {
              tronWeb?: Record<string, unknown>
              tronLink?: { tronWeb?: Record<string, unknown> }
            }
            tronWeb = (windowWithTron.tronWeb || windowWithTron.tronLink?.tronWeb) || null
            if (tronWeb) {
              defaultAddress = tronWeb.defaultAddress as { base58?: string } | undefined
            }
          }
        }
        
        if (!defaultAddress?.base58) {
          throw new Error('Please use the "request" method first to connect your Tron account. defaultAddress.base58 is not available in tronWeb.')
        }

        const address = defaultAddress.base58
        onResult(address)
      } else if (method === 'signAndBroadcast') {
        if (!transactionJson.trim()) {
          throw new Error('Transaction JSON is required')
        }

        let transaction
        try {
          transaction = JSON.parse(transactionJson)
        } catch (e) {
          throw new Error('Invalid JSON format for transaction')
        }

        if (!tronWeb.trx || typeof tronWeb.trx !== 'object') {
          throw new Error('trx object not available in tronWeb')
        }

        const trx = tronWeb.trx as Record<string, unknown>

        if (!trx.sign || typeof trx.sign !== 'function') {
          throw new Error('trx.sign method not available')
        }

        const signMethod = trx.sign as (tx: unknown) => Promise<unknown>
        const signedTransaction = await signMethod(transaction)

        if (!trx.broadcast || typeof trx.broadcast !== 'function') {
          throw new Error('trx.broadcast method not available')
        }

        // TODO: Uncomment on fix bug on extension
        // const broadcastMethod = trx.broadcast as (tx: unknown) => Promise<unknown>
        // const broadcastResult = await broadcastMethod(signedTransaction)

        onResult({
          signedTransaction,
          broadcastResult: 'not available',
        })
      }
    } catch (err) {
      onError(useTronLink ? `TronLink: ${(err as Error).message || 'Unknown error'}` : (err as Error).message || 'Unknown error')
    } finally {
      if (useTronLink) {
        setLoadingTronLink(false)
      } else {
        setLoading(false)
      }
    }
  }

  const handleExecuteWithTronLink = async (): Promise<void> => {
    await handleExecute(true)
  }

  return (
    <div className="space-y-3">
      <div>
        <label className="block text-xs font-medium text-gray-700 mb-1">
          Method
        </label>
        <select
          value={method}
          onChange={(e) => setMethod(e.target.value)}
          className="w-full px-3 py-2 text-xs font-mono border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 bg-white"
        >
          {availableMethods.map((m) => (
            <option key={m.value} value={m.value}>
              {m.label} - {m.description}
            </option>
          ))}
        </select>
      </div>
      {method === 'signAndBroadcast' && (
        <>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="block text-xs font-medium text-gray-700 mb-1">
                From Address <span className="text-red-500">*</span>
              </label>
              <div className="flex gap-2">
                <input
                  type="text"
                  value={fromAddress}
                  onChange={(e) => setFromAddress(e.target.value)}
                  placeholder="T... (Base58 address)"
                  className="flex-1 px-3 py-2 text-xs font-mono border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                />
                <button
                  onClick={fetchDefaultAddress}
                  disabled={loadingAddress}
                  className="px-3 py-2 text-xs bg-blue-600 text-white rounded hover:bg-blue-700 disabled:bg-gray-400 disabled:cursor-not-allowed transition-colors whitespace-nowrap"
                  title="Fetch default address from tronWeb"
                >
                  {loadingAddress ? 'Loading...' : 'Fetch'}
                </button>
              </div>
            </div>

            <div>
              <label className="block text-xs font-medium text-gray-700 mb-1">
                To Address
              </label>
              <input
                type="text"
                value={toAddress}
                onChange={(e) => setToAddress(e.target.value)}
                placeholder="T... (Base58 address)"
                className="w-full px-3 py-2 text-xs font-mono border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
              />
            </div>
          </div>

          <div>
            <div className="flex items-center justify-between mb-2">
              <label className="block text-xs font-medium text-gray-700">
                Transaction Example <span className="text-red-500">*</span>
              </label>
              <select
                value={selectedExample}
                onChange={(e) => {
                  const value = e.target.value as TronExampleType | ''
                  setSelectedExample(value)
                  if (value) {
                    handleLoadExample(value)
                  }
                }}
                disabled={loadingExample}
                className="text-xs px-2 py-1 border border-gray-300 rounded bg-white hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-blue-500 disabled:bg-gray-100 disabled:cursor-not-allowed"
              >
                <option value="">Select Example...</option>
                {exampleOptions.map((option) => (
                  <option key={option.value} value={option.value}>
                    {option.label}
                  </option>
                ))}
              </select>
              {loadingExample && (
                <span className="text-xs text-gray-500 ml-2">Loading block data...</span>
              )}
            </div>
            <textarea
              value={transactionJson}
              onChange={(e) => setTransactionJson(e.target.value)}
              placeholder='{"raw_data": {...}}'
              className="w-full px-3 py-2 text-xs font-mono border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 resize-y min-h-[200px]"
              rows={10}
            />
            <p className="text-xs text-gray-500 mt-1">
              JSON transaction object in TronWeb format. Select an example from the
              dropdown to load a template. You can edit the transaction before
              signing and broadcasting.
            </p>
          </div>
        </>
      )}
      <div className="space-y-3">
        <button
          onClick={() => handleExecute()}
          disabled={loading || loadingTronLink || (method === 'signAndBroadcast' && (!transactionJson.trim() || !fromAddress.trim()))}
          className="w-full px-4 py-2 text-sm bg-blue-600 text-white rounded hover:bg-blue-700 disabled:bg-gray-400 disabled:cursor-not-allowed transition-colors"
        >
          {loading
            ? method === 'signAndBroadcast'
              ? 'Signing & Broadcasting...'
              : 'Getting Address...'
            : method === 'signAndBroadcast'
              ? 'Sign & Broadcast Transaction'
              : 'Get Default Address'}
        </button>
        
        <div className="border-t border-gray-200 pt-3">
          <div className="text-xs text-gray-500 mb-2">
            <span className="font-medium">Comparison:</span> Test signing with TronLink extension
          </div>
          <button
            onClick={handleExecuteWithTronLink}
            disabled={loadingTronLink || loading || (method === 'signAndBroadcast' && (!transactionJson.trim() || !fromAddress.trim())) || !((window as unknown as { tronWeb?: unknown; tronLink?: { tronWeb?: unknown } }).tronWeb || (window as unknown as { tronLink?: { tronWeb?: unknown } }).tronLink?.tronWeb)}
            className="w-full px-3 py-2 text-xs bg-purple-50 border border-purple-200 text-purple-700 rounded hover:bg-purple-100 disabled:bg-gray-50 disabled:text-gray-400 disabled:border-gray-200 disabled:cursor-not-allowed transition-colors"
            title="Sign and Broadcast with TronLink extension (for comparison)"
          >
            {loadingTronLink || loading
              ? (loadingTronLink ? 'Signing with TronLink...' : 'Broadcasting...')
              : method === 'signAndBroadcast'
                ? 'Sign & Broadcast with TronLink'
                : 'Get Default Address with TronLink'}
          </button>
        </div>
      </div>
    </div>
  )
}

export const TronWebMethod = TronWebMethodComponent

