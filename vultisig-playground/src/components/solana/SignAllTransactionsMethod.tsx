import { useState, useCallback } from 'react'
import { VersionedTransaction } from '@solana/web3.js'
import { Buffer } from 'buffer'
import type { SolanaWalletProvider } from './types'
import { getMultipleSolanaTransactions, type TransactionMeta } from './solanaExamples'

interface SignAllTransactionsMethodProps {
  provider: unknown
  onResult: (result: unknown) => void
  onError: (error: string) => void
  onAccountUpdate?: (accounts: string[]) => void
}

export function SignAllTransactionsMethod({ onResult, onError }: SignAllTransactionsMethodProps) {
  const SLOTS = 20
  const [transactionsBase64, setTransactionsBase64] = useState<string[]>(Array(SLOTS).fill(''))
  const [transactionMeta, setTransactionMeta] = useState<(TransactionMeta | null)[]>(Array(SLOTS).fill(null))
  const [fromAddress, setFromAddress] = useState<string>('')
  const [toAddress, setToAddress] = useState<string>('')
  const [numTransactions, setNumTransactions] = useState<number>(8)
  const [loading, setLoading] = useState<boolean>(false)
  const [loadingPhantom, setLoadingPhantom] = useState<boolean>(false)
  const [loadingExample, setLoadingExample] = useState<boolean>(false)

  const fetchPublicKey = useCallback(async (): Promise<void> => {
    const solanaProvider = window.vultisig?.solana as SolanaWalletProvider | undefined
    if (!solanaProvider) {
      onError('Solana provider not available')
      return
    }

    try {
      if (solanaProvider.publicKey) {
        let publicKey: string
        if (typeof solanaProvider.publicKey === 'string') {
          publicKey = solanaProvider.publicKey
        } else if (typeof solanaProvider.publicKey === 'object' && 'toString' in solanaProvider.publicKey) {
          publicKey = solanaProvider.publicKey.toString()
        } else {
          throw new Error('publicKey format is not recognized')
        }
        setFromAddress(publicKey)
      } else {
        throw new Error('publicKey not available. Please connect first.')
      }
    } catch (err) {
      onError((err as Error).message || 'Failed to fetch public key')
    }
  }, [onError])

  const handleLoadExample = useCallback(async (): Promise<void> => {
    if (!fromAddress) {
      onError('Please fetch or enter a from address first')
      return
    }

    setLoadingExample(true)
    onError('')
    try {
      const { transactions, meta } = await getMultipleSolanaTransactions(fromAddress, toAddress)
      if (!Array.isArray(transactions) || transactions.length === 0) {
        onError('No se recibieron transacciones del ejemplo')
        return
      }
      const asStrings = transactions.map((t) => (typeof t === 'string' ? t : ''))
      const filled = [...asStrings, ...Array(Math.max(0, SLOTS - asStrings.length)).fill('')].slice(0, SLOTS)
      const metaFilled = [...meta, ...Array(Math.max(0, SLOTS - meta.length)).fill(null)].slice(0, SLOTS) as (TransactionMeta | null)[]
      setTransactionsBase64(filled)
      setTransactionMeta(metaFilled)
      setNumTransactions(asStrings.length)
    } catch (err) {
      console.error('Error loading example:', err)
      onError((err as Error).message || 'Failed to load example')
    } finally {
      setLoadingExample(false)
    }
  }, [fromAddress, toAddress, onError])

  const handleSignAllTransactions = async (usePhantom: boolean = false): Promise<void> => {
    // Only use the first numTransactions transactions
    const transactionsToUse = transactionsBase64.slice(0, numTransactions)
    const validTransactions = transactionsToUse.filter(tx => tx.trim())
    
    if (validTransactions.length === 0) {
      onError('At least one transaction (Base64) is required. Please load the example or enter transactions.')
      return
    }
    
    if (validTransactions.length < numTransactions) {
      onError(`Expected ${numTransactions} transactions but only ${validTransactions.length} are provided.`)
      return
    }

    let solanaProvider: SolanaWalletProvider | null = null

    if (usePhantom) {
      const windowWithPhantom = window as unknown as { phantom?: { solana?: SolanaWalletProvider } }
      solanaProvider = windowWithPhantom.phantom?.solana || null
      if (!solanaProvider) {
        onError('Phantom extension not available')
        return
      }
      setLoadingPhantom(true)
    } else {
      solanaProvider = window.vultisig?.solana as SolanaWalletProvider | undefined || null
      if (!solanaProvider) {
        onError('Solana provider not available')
        return
      }
      setLoading(true)
    }

    try {
      if (!solanaProvider.signAllTransactions || typeof solanaProvider.signAllTransactions !== 'function') {
        throw new Error('signAllTransactions method is not available')
      }

      const web3Transactions = validTransactions.map(txBase64 => {
        const transactionBuffer = Buffer.from(txBase64, 'base64')
        const transactionBytes = new Uint8Array(transactionBuffer)
        return VersionedTransaction.deserialize(transactionBytes)
      })

      const result = await solanaProvider.signAllTransactions(web3Transactions)
      onResult(result)
    } catch (err) {
      onError(usePhantom ? `Phantom: ${(err as Error).message || 'Unknown error'}` : (err as Error).message || 'Unknown error')
    } finally {
      if (usePhantom) {
        setLoadingPhantom(false)
      } else {
        setLoading(false)
      }
    }
  }

  const handleSignAllTransactionsWithPhantom = async (): Promise<void> => {
    await handleSignAllTransactions(true)
  }

  const updateTransaction = (index: number, value: string) => {
    const newTransactions = [...transactionsBase64]
    newTransactions[index] = value
    setTransactionsBase64(newTransactions)
    setTransactionMeta((prev) => {
      const next = [...prev]
      next[index] = null
      return next
    })
  }

  return (
    <div className="space-y-3">
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
              placeholder="Solana address (Base58)"
              className="flex-1 px-3 py-2 text-xs font-mono border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
            />
            <button
              onClick={fetchPublicKey}
              disabled={loadingExample}
              className="px-3 py-2 text-xs bg-blue-600 text-white rounded hover:bg-blue-700 disabled:bg-gray-400 disabled:cursor-not-allowed transition-colors whitespace-nowrap"
              title="Fetch public key from connected wallet"
            >
              {loadingExample ? 'Loading...' : 'Fetch'}
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
            placeholder="Solana address (Base58)"
            className="w-full px-3 py-2 text-xs font-mono border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
          />
        </div>
      </div>

      <div>
        <div className="flex items-center justify-between mb-2">
          <label className="block text-xs font-medium text-gray-700">
            Example Transactions
          </label>
          <button
            onClick={handleLoadExample}
            disabled={loadingExample || !fromAddress}
            className="px-3 py-1 text-xs bg-green-600 text-white rounded hover:bg-green-700 disabled:bg-gray-400 disabled:cursor-not-allowed transition-colors"
          >
            {loadingExample ? 'Loading...' : 'Load Example (20 Transactions)'}
          </button>
        </div>
        <p className="text-xs text-gray-500 mb-2">
          Load an example with 20 transactions: mix of SOL and USDC transfers
        </p>
      </div>

      <div>
        <label className="block text-xs font-medium text-gray-700 mb-1">
          Number of Transactions to Sign (1-20)
        </label>
        <div className="flex items-center gap-2">
          <input
            type="number"
            min="1"
            max="20"
            value={numTransactions}
            onChange={(e) => {
              const value = parseInt(e.target.value, 10)
              if (!isNaN(value) && value >= 1 && value <= SLOTS) {
                setNumTransactions(value)
              }
            }}
            className="w-20 px-3 py-2 text-xs border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
          />
          <span className="text-xs text-gray-500">
            Will sign the first {numTransactions} transaction{numTransactions !== 1 ? 's' : ''}
          </span>
        </div>
      </div>

      <div className="space-y-3">
        {transactionsBase64.map((tx, index) => {
          const isIncluded = index < numTransactions
          
          return (
            <div key={index} className={!isIncluded ? 'opacity-50' : ''}>
              <label className="block text-xs font-medium text-gray-700 mb-1">
                Transaction {index + 1}
                {transactionMeta[index] != null && (
                  <span className="ml-2 text-gray-600">
                    ({transactionMeta[index]!.amount} {transactionMeta[index]!.type})
                  </span>
                )}
                {!isIncluded && <span className="ml-2 text-gray-400">(Not included)</span>}
                {isIncluded && <span className="ml-2 text-green-600">(Will be signed)</span>}
              </label>
              <textarea
                value={tx || ''}
                onChange={(e) => updateTransaction(index, e.target.value)}
                placeholder="Enter Base64 encoded transaction"
                disabled={!isIncluded}
                className={`w-full px-3 py-2 text-xs font-mono border rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 resize-y min-h-[100px] ${
                  isIncluded 
                    ? 'border-gray-300' 
                    : 'border-gray-200 bg-gray-50 cursor-not-allowed'
                }`}
                rows={5}
              />
            </div>
          )
        })}
      </div>

      <div className="space-y-3">
        <button
          onClick={() => handleSignAllTransactions()}
          disabled={loading || loadingPhantom || transactionsBase64.slice(0, numTransactions).every(tx => !tx.trim())}
          className="w-full px-4 py-2 text-sm bg-blue-600 text-white rounded hover:bg-blue-700 disabled:bg-gray-400 disabled:cursor-not-allowed transition-colors"
        >
          {loading ? `Signing ${numTransactions} Transaction${numTransactions !== 1 ? 's' : ''}...` : `Sign ${numTransactions} Transaction${numTransactions !== 1 ? 's' : ''}`}
        </button>
        
        <div className="border-t border-gray-200 pt-3">
          <div className="text-xs text-gray-500 mb-2">
            <span className="font-medium">Comparison:</span> Test signing all transactions with Phantom extension
          </div>
          <button
            onClick={handleSignAllTransactionsWithPhantom}
            disabled={loadingPhantom || loading || transactionsBase64.slice(0, numTransactions).every(tx => !tx.trim()) || !((window as unknown as { phantom?: { solana?: unknown } }).phantom?.solana)}
            className="w-full px-3 py-2 text-xs bg-purple-50 border border-purple-200 text-purple-700 rounded hover:bg-purple-100 disabled:bg-gray-50 disabled:text-gray-400 disabled:border-gray-200 disabled:cursor-not-allowed transition-colors"
            title="Sign transactions with Phantom extension (for comparison)"
          >
            {loadingPhantom || loading
              ? (loadingPhantom ? `Signing ${numTransactions} with Phantom...` : `Signing ${numTransactions}...`)
              : `Sign ${numTransactions} Transaction${numTransactions !== 1 ? 's' : ''} with Phantom`}
          </button>
        </div>
      </div>
    </div>
  )
}
