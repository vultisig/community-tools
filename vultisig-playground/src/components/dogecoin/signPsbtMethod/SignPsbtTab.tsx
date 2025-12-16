interface SignPsbtTabProps {
  psbt: string
  loading: boolean
  onPsbtChange: (psbt: string) => void
  onSignPsbt: () => void
}

export function SignPsbtTab({
  psbt,
  loading,
  onPsbtChange,
  onSignPsbt,
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
      <button
        onClick={onSignPsbt}
        disabled={loading || !psbt.trim()}
        className="w-full px-4 py-2 text-sm font-medium bg-blue-600 text-white rounded hover:bg-blue-700 disabled:bg-gray-400 disabled:cursor-not-allowed transition-colors"
      >
        {loading ? 'Signing...' : 'Sign with Vultisig'}
      </button>
    </div>
  )
}



