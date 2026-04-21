import { useState } from 'react'
import type { MethodComponentProps } from './types'
import { formatCip30Error, formatLovelace, getEnabledApi } from './cardanoUtils'
import { buildSampleUnsignedTx, buildSignedTx } from './sampleTxBuilder'

export function SignTxMethod({ provider, onResult, onError }: MethodComponentProps) {
  const [txHex, setTxHex] = useState('')
  const [partialSign, setPartialSign] = useState(false)
  const [bodyBytes, setBodyBytes] = useState<Uint8Array | null>(null)
  const [witnessSetHex, setWitnessSetHex] = useState<string | null>(null)
  const [signedTxHex, setSignedTxHex] = useState<string | null>(null)
  const [sampleSummary, setSampleSummary] = useState<{
    inputTxHash: string
    inputIndex: number
    outputAddressHex: string
    outputLovelace: string
    feeLovelace: string
    ttl: number
  } | null>(null)
  const [buildingSample, setBuildingSample] = useState(false)
  const [signing, setSigning] = useState(false)

  const handleBuildSample = async () => {
    setBuildingSample(true)
    setWitnessSetHex(null)
    setSignedTxHex(null)
    try {
      const api = await getEnabledApi(provider)
      const built = await buildSampleUnsignedTx(api)
      setTxHex(built.unsignedTxHex)
      setBodyBytes(built.bodyBytes)
      setSampleSummary({
        inputTxHash: built.inputTxHash,
        inputIndex: built.inputIndex,
        outputAddressHex: built.outputAddressHex,
        outputLovelace: built.outputLovelace,
        feeLovelace: built.feeLovelace,
        ttl: built.ttl,
      })
    } catch (err) {
      onError(formatCip30Error(err))
    } finally {
      setBuildingSample(false)
    }
  }

  const handleSign = async () => {
    if (!txHex.trim()) {
      onError('Transaction CBOR hex is required')
      return
    }
    setSigning(true)
    setWitnessSetHex(null)
    setSignedTxHex(null)
    try {
      const api = await getEnabledApi(provider)
      const witness = await api.signTx(txHex.trim(), partialSign)
      setWitnessSetHex(witness)
      const signed = bodyBytes ? buildSignedTx(bodyBytes, witness) : null
      if (signed) setSignedTxHex(signed)
      onResult({
        witnessSetHex: witness,
        signedTxHex: signed,
        note: signed
          ? 'Signed tx built from the sample body. Copy signedTxHex into the submitTx tab.'
          : 'Witness set returned. The dApp must combine it with the tx body to produce a submittable CBOR.',
      })
    } catch (err) {
      onError(formatCip30Error(err))
    } finally {
      setSigning(false)
    }
  }

  return (
    <div className="space-y-3">
      <p className="text-xs text-gray-600">
        Signs a Cardano transaction. The wallet hashes the tx body and returns a CBOR witness set.
      </p>

      <div className="bg-indigo-50 border border-indigo-200 rounded-md p-3 space-y-2">
        <div className="flex items-center justify-between">
          <span className="text-xs font-semibold text-indigo-900">Sample transaction builder</span>
          <button
            onClick={handleBuildSample}
            disabled={buildingSample}
            className="px-3 py-1.5 text-xs bg-indigo-600 text-white rounded hover:bg-indigo-700 disabled:bg-gray-400 disabled:cursor-not-allowed transition-colors"
          >
            {buildingSample ? 'Building…' : 'Build sample tx'}
          </button>
        </div>
        <p className="text-xs text-indigo-800">
          Builds a 1-input / 1-output self-transfer using the largest lovelace-only UTXO. Fee: 0.2
          ADA. TTL fetched from api.vultisig.com/cardano/tip.
        </p>
        {sampleSummary && (
          <div className="text-xs font-mono text-indigo-900 bg-white rounded p-2 space-y-1 break-all">
            <div>
              <span className="font-semibold">input:</span> {sampleSummary.inputTxHash}#
              {sampleSummary.inputIndex}
            </div>
            <div>
              <span className="font-semibold">output:</span>{' '}
              {formatLovelace(BigInt(sampleSummary.outputLovelace))} → {sampleSummary.outputAddressHex}
            </div>
            <div>
              <span className="font-semibold">fee:</span>{' '}
              {formatLovelace(BigInt(sampleSummary.feeLovelace))}
            </div>
            <div>
              <span className="font-semibold">TTL slot:</span> {sampleSummary.ttl}
            </div>
          </div>
        )}
      </div>

      <div>
        <label className="block text-xs font-medium text-gray-700 mb-1">
          Transaction CBOR hex <span className="text-red-500">*</span>
        </label>
        <textarea
          value={txHex}
          onChange={(e) => {
            setTxHex(e.target.value)
            setBodyBytes(null)
            setSampleSummary(null)
            setWitnessSetHex(null)
            setSignedTxHex(null)
          }}
          placeholder="84a4...  (hex-encoded CBOR transaction)"
          className="w-full px-3 py-2 text-xs font-mono border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 resize-y"
          rows={5}
        />
      </div>

      <label className="flex items-center gap-2 text-xs text-gray-700">
        <input
          type="checkbox"
          checked={partialSign}
          onChange={(e) => setPartialSign(e.target.checked)}
          className="rounded"
        />
        partialSign (do not error if wallet cannot sign all required witnesses)
      </label>

      <button
        onClick={handleSign}
        disabled={signing || !txHex.trim()}
        className="w-full px-4 py-2 text-sm bg-blue-600 text-white rounded hover:bg-blue-700 disabled:bg-gray-400 disabled:cursor-not-allowed transition-colors"
      >
        {signing ? 'Signing…' : 'Call signTx()'}
      </button>

      {(witnessSetHex || signedTxHex) && (
        <div className="border-t border-gray-200 pt-3 space-y-2 text-xs">
          {witnessSetHex && (
            <div className="break-all font-mono">
              <span className="font-semibold text-gray-700">witness set hex:</span>
              <div className="mt-1 p-2 bg-gray-50 rounded">{witnessSetHex}</div>
            </div>
          )}
          {signedTxHex && (
            <div className="break-all font-mono">
              <span className="font-semibold text-gray-700">
                signed tx hex (ready for submitTx):
              </span>
              <div className="mt-1 p-2 bg-green-50 border border-green-200 rounded">
                {signedTxHex}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  )
}
