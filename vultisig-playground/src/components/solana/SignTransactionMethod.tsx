import { useState, useCallback } from 'react'
import { VersionedTransaction, PublicKey } from '@solana/web3.js'
import { verify } from '@solana/web3.js/src/utils/ed25519.js'
import type { SolanaWalletProvider } from './types'
import {
  getSolanaTransactionExamples,
  getSolanaExampleDescriptions,
  type SolanaExampleType,
  type PartiallySignedTransactionResult,
} from './solanaExamples'

interface SignTransactionMethodProps {
  provider: unknown
  onResult: (result: unknown) => void
  onError: (error: string) => void
  onAccountUpdate?: (accounts: string[]) => void
}

export function SignTransactionMethod({ onResult, onError }: SignTransactionMethodProps) {
  const [transactionBase64, setTransactionBase64] = useState<string>('')
  const [selectedExample, setSelectedExample] = useState<SolanaExampleType | ''>('')
  const [fromAddress, setFromAddress] = useState<string>('')
  const [toAddress, setToAddress] = useState<string>('')
  const [loading, setLoading] = useState<boolean>(false)
  const [loadingPhantom, setLoadingPhantom] = useState<boolean>(false)
  const [loadingExample, setLoadingExample] = useState<boolean>(false)
  const [partialSignerPublicKey, setPartialSignerPublicKey] = useState<string | null>(null)
  const [signatureVerification, setSignatureVerification] = useState<string | null>(null)

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
        
        if (typeof exampleResult === 'object' && 'transaction' in exampleResult) {
          const partiallySignedResult = exampleResult as PartiallySignedTransactionResult
          setTransactionBase64(partiallySignedResult.transaction)
          setPartialSignerPublicKey(partiallySignedResult.partialSignerPublicKey)
        } else {
          setTransactionBase64(exampleResult as string)
          setPartialSignerPublicKey(null)
        }
        
        setSignatureVerification(null)
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

  const handleSignTransaction = async (usePhantom: boolean = false): Promise<void> => {
    if (!transactionBase64.trim()) {
      onError('Transaction (Base64) is required. Please select an example or enter a transaction.')
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
      if (!solanaProvider.signTransaction || typeof solanaProvider.signTransaction !== 'function') {
        throw new Error('signTransaction method is not available')
      }

      const transactionBuffer = Buffer.from(transactionBase64, 'base64')
      const transactionBytes = new Uint8Array(transactionBuffer)
      const web3Transaction = VersionedTransaction.deserialize(transactionBytes)
      
      const result = await solanaProvider.signTransaction(web3Transaction)
      
      try {
        let signedTransaction: VersionedTransaction
        if (result instanceof VersionedTransaction) {
          signedTransaction = result
        } else if (result && typeof result === 'object' && 'serialize' in result) {
          const serialized = (result as { serialize: () => Uint8Array }).serialize()
          signedTransaction = VersionedTransaction.deserialize(serialized)
        } else {
          const resultObj = result as { transaction?: VersionedTransaction }
          if (resultObj?.transaction instanceof VersionedTransaction) {
            signedTransaction = resultObj.transaction
          } else {
            throw new Error('Could not extract signed transaction from result')
          }
        }
        
        const numRequiredSignatures = signedTransaction.message.header.numRequiredSignatures
        
        if (signedTransaction.signatures.length < numRequiredSignatures) {
          setSignatureVerification(`❌ Insufficient signatures: ${signedTransaction.signatures.length} of ${numRequiredSignatures} required`)
          onResult(result)
          return
        }
        
        const messageData = signedTransaction.message.serialize()
        
        const signerPubkeys = signedTransaction.message.staticAccountKeys.slice(
          0,
          numRequiredSignatures
        )
        
        interface SignatureVerificationResult {
          index: number
          publicKey: PublicKey
          isValid: boolean
          isPresent: boolean
          error?: string
        }
        
        const signatureResults: SignatureVerificationResult[] = []
        
        for (let i = 0; i < numRequiredSignatures && i < signedTransaction.signatures.length; i++) {
          const signature = signedTransaction.signatures[i]
          const publicKey = signerPubkeys[i]
          
          const isPresent = !signature.every(byte => byte === 0)
          
          if (!isPresent) {
            signatureResults.push({
              index: i,
              publicKey,
              isValid: false,
              isPresent: false,
            })
            continue
          }
          
          try {
            const signatureLength = signature.length
            const expectedSignatureLength = 64
            
            if (signatureLength !== expectedSignatureLength) {
              signatureResults.push({
                index: i,
                publicKey,
                isValid: false,
                isPresent: true,
                error: `Invalid signature length: ${signatureLength} bytes (expected ${expectedSignatureLength})`,
              })
              continue
            }
            
            const isValid = verify(signature, messageData, publicKey.toBytes())
            if (!isValid) {
              try {
                signatureResults.push({
                  index: i,
                  publicKey,
                  isValid: false,
                  isPresent: true,
                  error: 'Signature verification failed (signature does not match public key and message)',
                })
              } catch (pubKeyErr) {
                signatureResults.push({
                  index: i,
                  publicKey,
                  isValid: false,
                  isPresent: true,
                  error: `Invalid public key format: ${(pubKeyErr as Error).message}`,
                })
              }
            } else {
              signatureResults.push({
                index: i,
                publicKey,
                isValid: true,
                isPresent: true,
              })
            }
          } catch (err) {
            signatureResults.push({
              index: i,
              publicKey,
              isValid: false,
              isPresent: true,
              error: `Verification error: ${(err as Error).message}`,
            })
          }
        }
        
        const allSignaturesValid = signatureResults.every(result => result.isValid)
        const allSignaturesPresent = signatureResults.length === numRequiredSignatures
        
        if (partialSignerPublicKey) {
          const partialSignerPubKey = new PublicKey(partialSignerPublicKey)
          
          const partialSignerIndex = signedTransaction.message.staticAccountKeys.findIndex(
            (key) => key.equals(partialSignerPubKey)
          )
          
          if (partialSignerIndex < 0) {
            setSignatureVerification(`⚠️ Partial signer public key not found in static account keys`)
            onResult(result)
            return
          }
          
          const partialSignatureResult = signatureResults.find(
            result => result.publicKey.equals(partialSignerPubKey)
          )
          
          const partialSignatureValid = partialSignatureResult?.isValid ?? false
          
          if (allSignaturesValid && allSignaturesPresent) {
            setSignatureVerification(`✅ All ${numRequiredSignatures} required signatures are cryptographically valid. Partial signature preserved and verified: ${partialSignerPublicKey.slice(0, 8)}...${partialSignerPublicKey.slice(-8)}`)
          } else if (partialSignatureValid && !allSignaturesValid) {
            const invalidSignatures = signatureResults
              .filter(result => !result.isValid)
              .map(result => {
                const pubKeyStr = result.publicKey.toBase58()
                const shortKey = `${pubKeyStr.slice(0, 8)}...${pubKeyStr.slice(-8)}`
                if (!result.isPresent) {
                  return `Signature ${result.index} missing (${shortKey})`
                } else if (result.error) {
                  return `Signature ${result.index} error (${shortKey}): ${result.error}`
                } else {
                  return `Signature ${result.index} INVALID (${shortKey})`
                }
              })
            
            setSignatureVerification(`⚠️ Partial signature is valid but ${invalidSignatures.length} other signature(s) invalid:\n${invalidSignatures.join('\n')}\n\nPartial signer: ${partialSignerPublicKey.slice(0, 8)}...${partialSignerPublicKey.slice(-8)}`)
          } else if (!partialSignatureValid) {
            if (partialSignatureResult && !partialSignatureResult.isPresent) {
              setSignatureVerification(`❌ Partial signature MISSING (replaced with zeros): ${partialSignerPublicKey.slice(0, 8)}...${partialSignerPublicKey.slice(-8)}`)
            } else if (partialSignatureResult?.error) {
              setSignatureVerification(`❌ Partial signature verification ERROR: ${partialSignatureResult.error}\nSigner: ${partialSignerPublicKey.slice(0, 8)}...${partialSignerPublicKey.slice(-8)}`)
            } else {
              setSignatureVerification(`❌ Partial signature is INVALID (cryptographic verification failed): ${partialSignerPublicKey.slice(0, 8)}...${partialSignerPublicKey.slice(-8)}`)
            }
          } else {
            const missingCount = numRequiredSignatures - signatureResults.length
            setSignatureVerification(`⚠️ Partial signature present but ${missingCount} required signature(s) missing: ${partialSignerPublicKey.slice(0, 8)}...${partialSignerPublicKey.slice(-8)}`)
          }
        } else {
          if (allSignaturesValid && allSignaturesPresent) {
            setSignatureVerification(`✅ All ${numRequiredSignatures} required signature(s) are cryptographically valid`)
          } else {
            const invalidSignatures = signatureResults
              .filter(result => !result.isValid)
              .map(result => {
                const pubKeyStr = result.publicKey.toBase58()
                const shortKey = `${pubKeyStr.slice(0, 8)}...${pubKeyStr.slice(-8)}`
                if (!result.isPresent) {
                  return `Signature ${result.index} missing (${shortKey})`
                } else if (result.error) {
                  return `Signature ${result.index} error (${shortKey}): ${result.error}`
                } else {
                  return `Signature ${result.index} INVALID (${shortKey})`
                }
              })
            
            if (invalidSignatures.length > 0) {
              setSignatureVerification(`❌ ${invalidSignatures.length} signature(s) invalid or missing:\n${invalidSignatures.join('\n')}`)
            } else {
              const missingCount = numRequiredSignatures - signatureResults.length
              setSignatureVerification(`⚠️ ${missingCount} required signature(s) missing`)
            }
          }
        }
      } catch (err) {
        setSignatureVerification(`⚠️ Error verifying signatures: ${(err as Error).message}`)
      }
      
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

  const handleSignTransactionWithPhantom = async (): Promise<void> => {
    await handleSignTransaction(true)
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
        <label className="block text-xs font-medium text-gray-700 mb-1 mt-3">
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
          Base64 encoded Solana transaction to sign. Select an example from the dropdown to load a template.
        </p>
        {partialSignerPublicKey && (
          <div className="mt-2 p-2 bg-blue-50 border border-blue-200 rounded text-xs">
            <p className="text-blue-800 font-medium">Partially signed transaction detected</p>
            <p className="text-blue-600 mt-1">
              Partial signer: <span className="font-mono">{partialSignerPublicKey.slice(0, 8)}...{partialSignerPublicKey.slice(-8)}</span>
            </p>
            <p className="text-blue-600 mt-1">
              After signing, it will be verified that this signature has been preserved.
            </p>
          </div>
        )}
        {signatureVerification && (
          <div className={`mt-2 p-2 border rounded text-xs ${
            signatureVerification.startsWith('✅') 
              ? 'bg-green-50 border-green-200 text-green-800'
              : signatureVerification.startsWith('❌')
              ? 'bg-red-50 border-red-200 text-red-800'
              : 'bg-yellow-50 border-yellow-200 text-yellow-800'
          }`}>
            <p className="font-medium">{partialSignerPublicKey ? 'Partial signature verification:' : 'Signature verification:'}</p>
            <p className="mt-1 whitespace-pre-line">{signatureVerification}</p>
          </div>
        )}
      </div>
      <div className="space-y-3">
        <button
          onClick={() => handleSignTransaction()}
          disabled={loading || loadingPhantom || !transactionBase64.trim()}
          className="w-full px-4 py-2 text-sm bg-blue-600 text-white rounded hover:bg-blue-700 disabled:bg-gray-400 disabled:cursor-not-allowed transition-colors"
        >
          {loading ? 'Signing...' : 'Sign Transaction'}
        </button>
        
        <div className="border-t border-gray-200 pt-3">
          <div className="text-xs text-gray-500 mb-2">
            <span className="font-medium">Comparison:</span> Test signing with Phantom extension
          </div>
          <button
            onClick={handleSignTransactionWithPhantom}
            disabled={loadingPhantom || loading || !transactionBase64.trim() || !((window as unknown as { phantom?: { solana?: unknown } }).phantom?.solana)}
            className="w-full px-3 py-2 text-xs bg-purple-50 border border-purple-200 text-purple-700 rounded hover:bg-purple-100 disabled:bg-gray-50 disabled:text-gray-400 disabled:border-gray-200 disabled:cursor-not-allowed transition-colors"
            title="Sign transaction with Phantom extension (for comparison)"
          >
            {loadingPhantom || loading
              ? (loadingPhantom ? 'Signing with Phantom...' : 'Signing...')
              : 'Sign Transaction with Phantom'}
          </button>
        </div>
      </div>
    </div>
  )
}

