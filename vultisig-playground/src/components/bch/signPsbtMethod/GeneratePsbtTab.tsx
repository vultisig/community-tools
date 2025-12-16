import { useState } from 'react'
import { Utxo } from '../../../lib/tx/btc/UtxoQueryClient'

interface GeneratePsbtTabProps {
  fromAddress: string
  toAddress: string
  amount: string
  opReturnData: string
  utxos: Utxo[]
  selectedUtxos: Set<string>
  loadingUtxos: boolean
  loading: boolean
  totalUtxosValue: bigint
  totalSelectedValue: bigint
  onFromAddressChange: (address: string) => void
  onToAddressChange: (address: string) => void
  onAmountChange: (amount: string) => void
  onOpReturnDataChange: (data: string) => void
  onFetchUtxos: () => void
  onError: (error: string) => void
  onToggleUtxo: (utxo: Utxo) => void
  onGeneratePsbt: (feeRate: string) => void
}

export function GeneratePsbtTab({
  fromAddress,
  toAddress,
  amount,
  opReturnData,
  utxos,
  selectedUtxos,
  loadingUtxos,
  loading,
  totalUtxosValue,
  totalSelectedValue,
  onFromAddressChange,
  onToAddressChange,
  onAmountChange,
  onOpReturnDataChange,
  onFetchUtxos,
  onError,
  onToggleUtxo,
  onGeneratePsbt,
}: GeneratePsbtTabProps) {
  const [feeRate, setFeeRate] = useState<string>('')

  const handleGeneratePsbt = (): void => {
    onGeneratePsbt(feeRate)
  }
  return (
    <div className="space-y-4">
      <div>
        <label className="block text-xs font-medium text-gray-700 mb-1">
          From Address
        </label>
        <input
          type="text"
          value={fromAddress}
          onChange={(e) => onFromAddressChange(e.target.value)}
          placeholder="Bitcoin address"
          className="w-full px-2 py-1 text-xs font-mono border border-gray-300 rounded focus:outline-none focus:ring-1 focus:ring-blue-500"
        />
      </div>

      <div>
        <label className="block text-xs font-medium text-gray-700 mb-1">
          To Address
        </label>
        <input
          type="text"
          value={toAddress}
          onChange={(e) => onToAddressChange(e.target.value)}
          placeholder="Bitcoin address"
          className="w-full px-2 py-1 text-xs font-mono border border-gray-300 rounded focus:outline-none focus:ring-1 focus:ring-blue-500"
        />
      </div>

      <div className="grid grid-cols-2 gap-3">
        <div>
          <label className="block text-xs font-medium text-gray-700 mb-1">
            Amount (BTC)
          </label>
          <input
            type="text"
            value={amount}
            onChange={(e) => onAmountChange(e.target.value)}
            placeholder="0.0"
            className="w-full px-2 py-1 text-xs border border-gray-300 rounded focus:outline-none focus:ring-1 focus:ring-blue-500"
          />
        </div>
        <div>
          <label className="block text-xs font-medium text-gray-700 mb-1">
            Fee Rate (sats/vbyte)
          </label>
          <input
            type="text"
            value={feeRate}
            onChange={(e) => setFeeRate(e.target.value)}
            placeholder="Required"
            className="w-full px-2 py-1 text-xs border border-gray-300 rounded focus:outline-none focus:ring-1 focus:ring-blue-500"
          />
        </div>
      </div>

      <div>
        <label className="block text-xs font-medium text-gray-700 mb-1">
          OP_RETURN Data (optional)
        </label>
        <input
          type="text"
          value={opReturnData}
          onChange={(e) => onOpReturnDataChange(e.target.value)}
          placeholder="Data for OP_RETURN output"
          className="w-full px-2 py-1 text-xs border border-gray-300 rounded focus:outline-none focus:ring-1 focus:ring-blue-500"
        />
      </div>

      <div>
        <div className="flex items-center justify-between mb-2">
          <label className="block text-xs font-medium text-gray-700">UTXOs</label>
          <button
            onClick={onFetchUtxos}
            disabled={loadingUtxos || !fromAddress.trim()}
            className="px-3 py-1 text-xs bg-blue-600 text-white rounded hover:bg-blue-700 disabled:bg-gray-400 disabled:cursor-not-allowed transition-colors"
          >
            {loadingUtxos ? 'Loading...' : 'Fetch UTXOs'}
          </button>
        </div>

        {utxos.length > 0 && (
          <div className="space-y-2 max-h-60 overflow-y-auto border border-gray-200 rounded p-2">
            <div className="text-xs text-gray-600 mb-2">
              Total: {totalUtxosValue.toString()} sats
              {selectedUtxos.size > 0 && (
                <span className="ml-2 text-blue-600">
                  Selected: {totalSelectedValue.toString()} sats
                </span>
              )}
            </div>
            {utxos.map((utxo) => {
              const utxoKey = `${utxo.hash}:${utxo.index}`
              const isSelected = selectedUtxos.has(utxoKey)
              return (
                <div
                  key={utxoKey}
                  onClick={() => onToggleUtxo(utxo)}
                  className={`p-2 text-xs border rounded cursor-pointer transition-colors ${
                    isSelected
                      ? 'border-blue-500 bg-blue-50'
                      : 'border-gray-200 hover:border-gray-300'
                  }`}
                >
                  <div className="flex items-center justify-between">
                    <div className="flex-1 min-w-0">
                      <div className="font-mono truncate">{utxo.hash}</div>
                      <div className="text-gray-600">
                        vout: {utxo.index} | {utxo.value.toString()} sats
                      </div>
                    </div>
                    <div className={`ml-2 w-4 h-4 border-2 rounded ${
                      isSelected ? 'bg-blue-600 border-blue-600' : 'border-gray-300'
                    }`}>
                      {isSelected && (
                        <svg className="w-full h-full text-white" fill="currentColor" viewBox="0 0 20 20">
                          <path fillRule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clipRule="evenodd" />
                        </svg>
                      )}
                    </div>
                  </div>
                </div>
              )
            })}
          </div>
        )}

        {utxos.length === 0 && !loadingUtxos && fromAddress.trim() && (
          <p className="text-xs text-gray-500 text-center py-4">
            No UTXOs found for this address
          </p>
        )}
        {!fromAddress.trim() && (
          <p className="text-xs text-gray-500 text-center py-4">
            Enter a from address to load UTXOs
          </p>
        )}
      </div>

      <button
        onClick={handleGeneratePsbt}
        disabled={loading || !fromAddress.trim() || !toAddress.trim() || !amount.trim() || utxos.length === 0}
        className="w-full px-4 py-2 text-sm bg-green-600 text-white rounded hover:bg-green-700 disabled:bg-gray-400 disabled:cursor-not-allowed transition-colors"
      >
        {loading ? 'Generating...' : 'Generate PSBT'}
      </button>
    </div>
  )
}

