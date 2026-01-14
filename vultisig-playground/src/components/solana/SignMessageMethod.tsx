import { useState } from 'react'
import type { SolanaWalletProvider } from './types'

interface SignMessageMethodProps {
  provider: unknown
  onResult: (result: unknown) => void
  onError: (error: string) => void
  onAccountUpdate?: (accounts: string[]) => void
}

export function SignMessageMethod({ onResult, onError }: SignMessageMethodProps) {
  const [message, setMessage] = useState<string>('')
  const [loading, setLoading] = useState<boolean>(false)
  const [loadingPhantom, setLoadingPhantom] = useState<boolean>(false)

  const handleSignMessage = async (usePhantom: boolean = false): Promise<void> => {
    if (!message.trim()) {
      onError('Message is required')
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
      if (!solanaProvider.signMessage || typeof solanaProvider.signMessage !== 'function') {
        throw new Error('signMessage method is not available')
      }

      const messageBytes = new TextEncoder().encode(message)
      const result = await solanaProvider.signMessage(messageBytes, 'utf8')
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

  const handleSignMessageWithPhantom = async (): Promise<void> => {
    await handleSignMessage(true)
  }

  return (
    <div className="space-y-3">
      <div>
        <label className="block text-xs font-medium text-gray-700 mb-1">
          Message <span className="text-red-500">*</span>
        </label>
        <textarea
          value={message}
          onChange={(e) => setMessage(e.target.value)}
          placeholder="Enter message to sign"
          className="w-full px-3 py-2 text-xs font-mono border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 resize-y min-h-[100px]"
          rows={5}
        />
        <p className="text-xs text-gray-500 mt-1">
          Message to sign with Solana wallet
        </p>
      </div>
      <div className="space-y-3">
        <button
          onClick={() => handleSignMessage()}
          disabled={loading || loadingPhantom || !message.trim()}
          className="w-full px-4 py-2 text-sm bg-blue-600 text-white rounded hover:bg-blue-700 disabled:bg-gray-400 disabled:cursor-not-allowed transition-colors"
        >
          {loading ? 'Signing...' : 'Sign Message'}
        </button>
        
        <div className="border-t border-gray-200 pt-3">
          <div className="text-xs text-gray-500 mb-2">
            <span className="font-medium">Comparison:</span> Test signing with Phantom extension
          </div>
          <button
            onClick={handleSignMessageWithPhantom}
            disabled={loadingPhantom || loading || !message.trim() || !((window as unknown as { phantom?: { solana?: unknown } }).phantom?.solana)}
            className="w-full px-3 py-2 text-xs bg-purple-50 border border-purple-200 text-purple-700 rounded hover:bg-purple-100 disabled:bg-gray-50 disabled:text-gray-400 disabled:border-gray-200 disabled:cursor-not-allowed transition-colors"
            title="Sign message with Phantom extension (for comparison)"
          >
            {loadingPhantom || loading
              ? (loadingPhantom ? 'Signing with Phantom...' : 'Signing...')
              : 'Sign Message with Phantom'}
          </button>
        </div>
      </div>
    </div>
  )
}

