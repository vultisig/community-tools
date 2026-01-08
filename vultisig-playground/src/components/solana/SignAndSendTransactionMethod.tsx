import { useState, useCallback } from 'react'
import { VersionedTransaction } from '@solana/web3.js'
import { Buffer } from 'buffer'
import type { SolanaWalletProvider } from './types'
import {
  getSolanaTransactionExamples,
  getSolanaExampleDescriptions,
  type SolanaExampleType,
  type PartiallySignedTransactionResult,
} from './solanaExamples'

interface SignAndSendTransactionMethodProps {
  provider: unknown
  onResult: (result: unknown) => void
  onError: (error: string) => void
  onAccountUpdate?: (accounts: string[]) => void
}

export function SignAndSendTransactionMethod({ onResult, onError }: SignAndSendTransactionMethodProps) {
  const [transactionBase64, setTransactionBase64] = useState<string>('')
  const [selectedExample, setSelectedExample] = useState<SolanaExampleType | ''>('')
  const [fromAddress, setFromAddress] = useState<string>('')
  const [toAddress, setToAddress] = useState<string>('')
  const [loading, setLoading] = useState<boolean>(false)
  const [loadingPhantom, setLoadingPhantom] = useState<boolean>(false)
  const [loadingExample, setLoadingExample] = useState<boolean>(false)

  const exampleDescriptions = getSolanaExampleDescriptions()

  const exampleOptions: Array<{ value: SolanaExampleType; label: string }> = [
    { value: 'transferSOL', label: exampleDescriptions.transferSOL },
    { value: 'transferUSDC', label: exampleDescriptions.transferUSDC },
    { value: 'transferSOLLegacy', label: exampleDescriptions.transferSOLLegacy },
    { value: 'transferUSDCLegacy', label: exampleDescriptions.transferUSDCLegacy },
    { value: 'partiallySignedSOL', label: exampleDescriptions.partiallySignedSOL },
  ]

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

  const handleLoadExample = useCallback(
    async (exampleType: SolanaExampleType): Promise<void> => {
      if (!fromAddress) {
        onError('Please fetch or enter a from address first')
        return
      }

      setLoadingExample(true)
      try {
        const exampleResult = await getSolanaTransactionExamples(fromAddress, toAddress, exampleType)
        
        const exampleBase64 = typeof exampleResult === 'object' && 'transaction' in exampleResult
          ? (exampleResult as PartiallySignedTransactionResult).transaction
          : (exampleResult as string)
        
        setTransactionBase64(exampleBase64)
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

  const handleSignAndSendTransaction = async (usePhantom: boolean = false): Promise<void> => {
    if (!transactionBase64.trim()) {
      onError('Transaction (Base64) is required')
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
      if (!solanaProvider.signAndSendTransaction || typeof solanaProvider.signAndSendTransaction !== 'function') {
        throw new Error('signAndSendTransaction method is not available')
      }

      const transactionBuffer = Buffer.from(transactionBase64, 'base64')
      const transactionBytes = new Uint8Array(transactionBuffer)
      const web3Transaction = VersionedTransaction.deserialize(transactionBytes)

      const result = await solanaProvider.signAndSendTransaction(web3Transaction)
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

  const handleSignAndSendTransactionWithPhantom = async (): Promise<void> => {
    await handleSignAndSendTransaction(true)
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
            Transaction Example <span className="text-red-500">*</span>
          </label>
          <select
            value={selectedExample}
            onChange={(e) => {
              const value = e.target.value as SolanaExampleType | ''
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
            <span className="text-xs text-gray-500 ml-2">Loading...</span>
          )}
        </div>
        <label className="block text-xs font-medium text-gray-700 mb-1">
          Transaction (Base64) <span className="text-red-500">*</span>
        </label>
        <textarea
          value={transactionBase64}
          onChange={(e) => setTransactionBase64(e.target.value)}
          placeholder="Enter Base64 encoded transaction or select an example"
          className="w-full px-3 py-2 text-xs font-mono border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 resize-y min-h-[100px]"
          rows={5}
        />
        <p className="text-xs text-gray-500 mt-1">
          Base64 encoded Solana transaction to sign and send. Select an example from the dropdown to load a template.
        </p>
      </div>
      <div className="space-y-3">
        <button
          onClick={() => handleSignAndSendTransaction()}
          disabled={loading || loadingPhantom || !transactionBase64.trim()}
          className="w-full px-4 py-2 text-sm bg-blue-600 text-white rounded hover:bg-blue-700 disabled:bg-gray-400 disabled:cursor-not-allowed transition-colors"
        >
          {loading ? 'Signing & Sending...' : 'Sign & Send Transaction'}
        </button>
        
        <div className="border-t border-gray-200 pt-3">
          <div className="text-xs text-gray-500 mb-2">
            <span className="font-medium">Comparison:</span> Test signing and sending with Phantom extension
          </div>
          <button
            onClick={handleSignAndSendTransactionWithPhantom}
            disabled={loadingPhantom || loading || !transactionBase64.trim() || !((window as unknown as { phantom?: { solana?: unknown } }).phantom?.solana)}
            className="w-full px-3 py-2 text-xs bg-purple-50 border border-purple-200 text-purple-700 rounded hover:bg-purple-100 disabled:bg-gray-50 disabled:text-gray-400 disabled:border-gray-200 disabled:cursor-not-allowed transition-colors"
            title="Sign and send transaction with Phantom extension (for comparison)"
          >
            {loadingPhantom || loading
              ? (loadingPhantom ? 'Signing & Sending with Phantom...' : 'Signing & Sending...')
              : 'Sign & Send Transaction with Phantom'}
          </button>
        </div>
      </div>
    </div>
  )
}

