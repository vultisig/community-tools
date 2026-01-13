import { useState, useCallback } from 'react'
import { VersionedTransaction } from '@solana/web3.js'
import { Buffer } from 'buffer'
import type { SolanaWalletProvider } from './types'
import { getMultipleSolanaTransactions } from './solanaExamples'

interface SignAllTransactionsMethodProps {
  provider: unknown
  onResult: (result: unknown) => void
  onError: (error: string) => void
  onAccountUpdate?: (accounts: string[]) => void
}

export function SignAllTransactionsMethod({ onResult, onError }: SignAllTransactionsMethodProps) {
  const [transactionsBase64, setTransactionsBase64] = useState<string[]>(['', ''])
  const [fromAddress, setFromAddress] = useState<string>('')
  const [toAddress, setToAddress] = useState<string>('')
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
    try {
      const transactions = await getMultipleSolanaTransactions(fromAddress, toAddress)
      setTransactionsBase64(transactions)
    } catch (err) {
      console.error('Error loading example:', err)
      onError((err as Error).message || 'Failed to load example')
    } finally {
      setLoadingExample(false)
    }
  }, [fromAddress, toAddress, onError])

  const handleSignAllTransactions = async (usePhantom: boolean = false): Promise<void> => {
    const validTransactions = transactionsBase64.filter(tx => tx.trim())
    
    if (validTransactions.length === 0) {
      onError('At least one transaction (Base64) is required. Please load the example or enter transactions.')
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
            {loadingExample ? 'Loading...' : 'Load Example (SOL + USDC)'}
          </button>
        </div>
        <p className="text-xs text-gray-500 mb-2">
          Load an example with two transactions: 0.01 SOL transfer and 0.1 USDC transfer
        </p>
      </div>

      <div className="space-y-3">
        <div>
          <label className="block text-xs font-medium text-gray-700 mb-1">
            Transaction 1 (SOL Transfer - Base64)
          </label>
          <textarea
            value={transactionsBase64[0] || ''}
            onChange={(e) => updateTransaction(0, e.target.value)}
            placeholder="Enter Base64 encoded SOL transfer transaction"
            className="w-full px-3 py-2 text-xs font-mono border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 resize-y min-h-[100px]"
            rows={5}
          />
        </div>

        <div>
          <label className="block text-xs font-medium text-gray-700 mb-1">
            Transaction 2 (USDC Transfer - Base64)
          </label>
          <textarea
            value={transactionsBase64[1] || ''}
            onChange={(e) => updateTransaction(1, e.target.value)}
            placeholder="Enter Base64 encoded USDC transfer transaction"
            className="w-full px-3 py-2 text-xs font-mono border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 resize-y min-h-[100px]"
            rows={5}
          />
        </div>
      </div>

      <div className="space-y-3">
        <button
          onClick={() => handleSignAllTransactions()}
          disabled={loading || loadingPhantom || transactionsBase64.every(tx => !tx.trim())}
          className="w-full px-4 py-2 text-sm bg-blue-600 text-white rounded hover:bg-blue-700 disabled:bg-gray-400 disabled:cursor-not-allowed transition-colors"
        >
          {loading ? 'Signing All Transactions...' : 'Sign All Transactions'}
        </button>
        
        <div className="border-t border-gray-200 pt-3">
          <div className="text-xs text-gray-500 mb-2">
            <span className="font-medium">Comparison:</span> Test signing all transactions with Phantom extension
          </div>
          <button
            onClick={handleSignAllTransactionsWithPhantom}
            disabled={loadingPhantom || loading || transactionsBase64.every(tx => !tx.trim()) || !((window as unknown as { phantom?: { solana?: unknown } }).phantom?.solana)}
            className="w-full px-3 py-2 text-xs bg-purple-50 border border-purple-200 text-purple-700 rounded hover:bg-purple-100 disabled:bg-gray-50 disabled:text-gray-400 disabled:border-gray-200 disabled:cursor-not-allowed transition-colors"
            title="Sign all transactions with Phantom extension (for comparison)"
          >
            {loadingPhantom || loading
              ? (loadingPhantom ? 'Signing All with Phantom...' : 'Signing All...')
              : 'Sign All Transactions with Phantom'}
          </button>
        </div>
      </div>
    </div>
  )
}
