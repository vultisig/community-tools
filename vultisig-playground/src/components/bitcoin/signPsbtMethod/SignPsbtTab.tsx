interface SignPsbtTabProps {
  psbt: string
  loading: boolean
  loadingPhantom: boolean
  broadcasting: boolean
  txid: string
  onPsbtChange: (psbt: string) => void
  onSignPsbt: () => void
  onSignPsbtWithPhantom: () => void
}

export function SignPsbtTab({
  psbt,
  loading,
  loadingPhantom,
  broadcasting,
  txid,
  onPsbtChange,
  onSignPsbt,
  onSignPsbtWithPhantom,
}: SignPsbtTabProps) {
  return (
    <div className="space-y-3">
      <div>
        <label className="block text-xs font-medium text-gray-700 mb-1">
          PSBT (Base64 string)
        </label>
        <textarea
          value={psbt}
          onChange={(e) => onPsbtChange(e.target.value)}
          placeholder="Enter PSBT string or paste generated PSBT"
          className="w-full px-3 py-2 text-xs font-mono border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 resize-y min-h-[100px]"
          rows={5}
        />
      </div>
      <div className="space-y-3">
        <button
          onClick={onSignPsbt}
          disabled={loading || broadcasting || !psbt.trim()}
          className="w-full px-4 py-2 text-sm font-medium bg-blue-600 text-white rounded hover:bg-blue-700 disabled:bg-gray-400 disabled:cursor-not-allowed transition-colors"
        >
          {loading || broadcasting 
            ? (loading ? 'Signing...' : 'Broadcasting...') 
            : 'Sign and Broadcast with Vultisig'}
        </button>
        
        <div className="border-t border-gray-200 pt-3">
          <div className="text-xs text-gray-500 mb-2">
            <span className="font-medium">Comparison:</span> Test signing with Phantom wallet
          </div>
          <button
            onClick={onSignPsbtWithPhantom}
            disabled={loadingPhantom || broadcasting || !psbt.trim() || !(window as unknown as { phantom?: { bitcoin?: unknown } }).phantom?.bitcoin}
            className="w-full px-3 py-2 text-xs bg-purple-50 border border-purple-200 text-purple-700 rounded hover:bg-purple-100 disabled:bg-gray-50 disabled:text-gray-400 disabled:border-gray-200 disabled:cursor-not-allowed transition-colors"
            title="Sign and Broadcast with Phantom (for comparison)"
          >
            {loadingPhantom || broadcasting 
              ? (loadingPhantom ? 'Signing with Phantom...' : 'Broadcasting...') 
              : 'Sign with Phantom'}
          </button>
        </div>
      </div>
      
      {txid && (
        <div className="p-3 bg-green-50 border border-green-200 rounded">
          <div className="text-xs font-medium text-green-800 mb-1">Transaction Broadcasted!</div>
          <div className="text-xs font-mono text-green-700 break-all">
            TXID: {txid}
          </div>
          <a
            href={`https://mempool.space/tx/${txid}`}
            target="_blank"
            rel="noopener noreferrer"
            className="text-xs text-blue-600 hover:underline mt-1 inline-block"
          >
            View on Mempool.space →
          </a>
        </div>
      )}
    </div>
  )
}

