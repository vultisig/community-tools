import { useRef, useState } from 'react'
import type { RippleProvider } from './types'
import { getRippleExample, rippleExamples } from './rippleExamples'
import { executeRippleTransaction, type RippleSignMode } from './rippleSigningPolicy'

interface SignTransactionMethodProps {
  provider: unknown
  onResult: (result: unknown) => void
  onError: (error: string) => void
  onAccountUpdate?: (accounts: string[]) => void
}

const legitExamples = rippleExamples.filter((e) => e.category === 'legit')
const adversarialExamples = rippleExamples.filter((e) => e.category === 'adversarial')

export function SignTransactionMethod({ provider, onResult, onError }: SignTransactionMethodProps) {
  const [transactionJson, setTransactionJson] = useState<string>('')
  const [selectedExampleId, setSelectedExampleId] = useState<string>('')
  const [mode, setMode] = useState<RippleSignMode>('sign')
  const [loading, setLoading] = useState<boolean>(false)
  const exampleRequestId = useRef(0)

  const selectedExample = getRippleExample(selectedExampleId)
  const isPresetSelected = selectedExample !== undefined

  const getProvider = (): RippleProvider | null => {
    const xrpl = provider as Partial<RippleProvider> | null
    if (!xrpl?.getAddress || !xrpl.signTransaction || !xrpl.submitTransaction) return null
    return xrpl as RippleProvider
  }

  const handleSelectExample = async (id: string): Promise<void> => {
    const requestId = ++exampleRequestId.current
    setSelectedExampleId(id)
    setTransactionJson('')
    setMode('sign')
    if (!id) return

    const example = getRippleExample(id)
    if (!example) return

    const xrpl = getProvider()
    if (!xrpl) {
      onError('XRPL provider not available')
      return
    }

    try {
      const { address } = await xrpl.getAddress()
      if (requestId !== exampleRequestId.current) return
      const tx = example.build(address)
      setTransactionJson(JSON.stringify(tx, null, 2))
    } catch (err) {
      if (requestId !== exampleRequestId.current) return
      onError((err as Error).message || 'Failed to build example')
    }
  }

  const handleTransactionChange = (value: string): void => {
    exampleRequestId.current += 1
    setSelectedExampleId('')
    setTransactionJson(value)
  }

  const handleSign = async (): Promise<void> => {
    if (!transactionJson.trim()) {
      onError('Transaction JSON is required. Select an example or paste raw XRPL JSON.')
      return
    }

    const xrpl = getProvider()
    if (!xrpl) {
      onError('XRPL provider or signing methods not available')
      return
    }

    let transaction: Record<string, unknown>
    try {
      transaction = JSON.parse(transactionJson) as Record<string, unknown>
    } catch (err) {
      onError(`Invalid JSON: ${(err as Error).message}`)
      return
    }

    setLoading(true)
    try {
      const result = await executeRippleTransaction({
        mode,
        isPresetSelected,
        transaction,
        provider: xrpl,
      })
      onResult(result)
    } catch (err) {
      onError((err as Error).message || 'Unknown error')
    } finally {
      setLoading(false)
    }
  }

  const submitMode = mode === 'submit'
  const buttonColor = submitMode
    ? 'bg-red-600 hover:bg-red-700'
    : 'bg-blue-600 hover:bg-blue-700'

  return (
    <div className="space-y-3">
      <p className="text-xs text-gray-600">
        Signs raw XRPL JSON. <span className="font-medium">Sign only</span> returns the signed tx_blob without
        broadcasting; <span className="font-medium">Sign &amp; submit</span> broadcasts to the network.
      </p>

      <div>
        <label htmlFor="ripple-tx-example" className="block text-xs font-medium text-gray-700 mb-1">
          Transaction example
        </label>
        <select
          id="ripple-tx-example"
          value={selectedExampleId}
          onChange={(e) => handleSelectExample(e.target.value)}
          className="w-full text-xs px-2 py-2 border border-gray-300 rounded bg-white hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-blue-500"
        >
          <option value="">Select example...</option>
          <optgroup label="Legit">
            {legitExamples.map((example) => (
              <option key={example.id} value={example.id}>
                {example.label}
              </option>
            ))}
          </optgroup>
          <optgroup label="Adversarial">
            {adversarialExamples.map((example) => (
              <option key={example.id} value={example.id}>
                {example.label}
              </option>
            ))}
          </optgroup>
        </select>
        {selectedExample && (
          <p className="text-xs text-gray-500 mt-1">{selectedExample.description}</p>
        )}
      </div>

      {selectedExample?.category === 'adversarial' && selectedExample.expectedWalletBehavior && (
        <div className="p-3 bg-amber-50 border border-amber-300 rounded text-xs">
          <p className="font-semibold text-amber-800">Expected wallet behavior</p>
          <p className="text-amber-700 mt-1">{selectedExample.expectedWalletBehavior}</p>
          <p className="text-amber-600 mt-2">
            Compare this against what the wallet actually shows/does when you sign.
          </p>
        </div>
      )}

      <div>
        <label htmlFor="ripple-tx-json" className="block text-xs font-medium text-gray-700 mb-1">
          Transaction (raw XRPL JSON) <span className="text-red-500">*</span>
        </label>
        <textarea
          id="ripple-tx-json"
          aria-required="true"
          value={transactionJson}
          onChange={(e) => handleTransactionChange(e.target.value)}
          placeholder="Select an example or paste raw XRPL JSON"
          className="w-full px-3 py-2 text-xs font-mono border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 resize-y min-h-[160px]"
          rows={10}
        />
        <p className="text-xs text-gray-500 mt-1">
          Account is filled from the connected address when you load an example. Editable — tweak fields freely.
        </p>
      </div>

      <fieldset className="flex gap-4 text-xs text-gray-700">
        <legend className="sr-only">Signing mode</legend>
        <label className="flex items-center gap-2">
          <input
            type="radio"
            name="ripple-sign-mode"
            checked={mode === 'sign'}
            onChange={() => setMode('sign')}
            className="focus:ring-2 focus:ring-blue-500"
          />
          Sign only (no broadcast)
        </label>
        <label className="flex items-center gap-2">
          <input
            type="radio"
            name="ripple-sign-mode"
            checked={submitMode}
            disabled={isPresetSelected}
            onChange={() => setMode('submit')}
            className="focus:ring-2 focus:ring-blue-500 disabled:cursor-not-allowed"
          />
          Sign &amp; submit (broadcasts)
        </label>
      </fieldset>

      {isPresetSelected && (
        <p className="text-xs text-amber-700">
          Bundled examples are sign-only. Edit the raw JSON to enable XRPL Mainnet broadcast.
        </p>
      )}

      <button
        onClick={handleSign}
        disabled={loading || !transactionJson.trim()}
        className={`w-full px-4 py-2 text-sm text-white rounded disabled:bg-gray-400 disabled:cursor-not-allowed transition-colors ${buttonColor}`}
      >
        {loading
          ? submitMode ? 'Submitting...' : 'Signing...'
          : submitMode ? 'Sign & submit' : 'Sign only'}
      </button>
    </div>
  )
}
