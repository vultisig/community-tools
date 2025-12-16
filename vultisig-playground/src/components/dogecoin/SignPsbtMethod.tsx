import { useState, useEffect } from 'react'
import { Buffer } from 'buffer'
import * as bitcoin from '@shapeshiftoss/bitcoinjs-lib'
import { UtxoQueryClient, Utxo, UtxoWithHex } from '../../lib/tx/btc/UtxoQueryClient'
import { PsbtBuilder } from '../../lib/tx/btc/psbtBuilder'

const dogeNetwork = {
  messagePrefix: "Dogecoin Signed Message Much Wow:",
  bip32: {
    public: {
      p2pkh: 49990397,
    },
    private: 87393172,
  },
  pubKeyHash: 30,
  scriptHash: 22,
  wif: 128,
  bech32: "",
} as unknown as bitcoin.networks.Network
import { GeneratePsbtTab } from './signPsbtMethod/GeneratePsbtTab'
import { SignPsbtTab } from './signPsbtMethod/SignPsbtTab'
import { useWalletConnection } from '../../hooks/useWalletConnection'

interface SignPsbtMethodProps {
  provider: unknown
  onResult: (result: unknown) => void
  onError: (error: string) => void
  onAccountUpdate?: (accounts: string[]) => void
}

export function SignPsbtMethod({ onResult, onError }: SignPsbtMethodProps) {
  const [mode, setMode] = useState<'generate' | 'sign'>('generate')
  const [psbt, setPsbt] = useState<string>('')
  const [psbtInstance, setPsbtInstance] = useState<bitcoin.Psbt | null>(null)
  const [selectedUtxosForPsbt, setSelectedUtxosForPsbt] = useState<Utxo[]>([])
  const [loading, setLoading] = useState<boolean>(false)

  const [fromAddress, setFromAddress] = useState<string>('')
  const [toAddress, setToAddress] = useState<string>('')
  const [amount, setAmount] = useState<string>('')
  const [opReturnData, setOpReturnData] = useState<string>('')
  
  const [utxos, setUtxos] = useState<UtxoWithHex[]>([])
  const [selectedUtxos, setSelectedUtxos] = useState<Set<string>>(new Set())
  const [loadingUtxos, setLoadingUtxos] = useState<boolean>(false)
  
  const { connectedAddress, ensureConnection } = useWalletConnection('dogecoin')

  useEffect(() => {
    if (connectedAddress) {
      setFromAddress(connectedAddress)
    }
  }, [connectedAddress])

  useEffect(() => {
    setLoading(false)
    onResult(undefined)
  }, [mode])

  useEffect(() => {
    setUtxos([])
    setSelectedUtxos(new Set())
  }, [fromAddress])

  const handleFetchUtxos = async (): Promise<void> => {
    if (!fromAddress.trim()) {
      onError('From address is required')
      return
    }

    setLoadingUtxos(true)
    try {
      const utxoClient = new UtxoQueryClient('DOGE', fromAddress)
      const fetchedUtxos = await utxoClient.fetch()
      setUtxos(fetchedUtxos)
      setSelectedUtxos(new Set())
    } catch (err) {
      onError((err as Error).message || 'Failed to fetch UTXOs')
      setUtxos([])
      setSelectedUtxos(new Set())
    } finally {
      setLoadingUtxos(false)
    }
  }

  const handleToggleUtxo = (utxo: Utxo): void => {
    const utxoKey = `${utxo.hash}:${utxo.index}`
    const newSelected = new Set(selectedUtxos)
    if (newSelected.has(utxoKey)) {
      newSelected.delete(utxoKey)
    } else {
      newSelected.add(utxoKey)
    }
    setSelectedUtxos(newSelected)
  }

  const handleGeneratePsbt = async (feeRate: string): Promise<void> => {
    if (!fromAddress.trim() || !toAddress.trim() || !amount.trim()) {
      onError('From address, to address, and amount are required')
      return
    }

    const amountFloat = parseFloat(amount)
    if (isNaN(amountFloat) || amountFloat <= 0) {
      onError('Amount must be greater than 0')
      return
    }

    const amountBigInt = BigInt(Math.round(amountFloat * 100000000))

    setLoading(true)
    try {
      const builder = new PsbtBuilder(dogeNetwork)
      
      let utxosToUse: UtxoWithHex[]
      if (selectedUtxos.size > 0) {
        utxosToUse = utxos.filter((utxo) => selectedUtxos.has(`${utxo.hash}:${utxo.index}`))
      } else {
        utxosToUse = utxos
      }

      if (utxosToUse.length === 0) {
        onError('No UTXOs available for this address.')
        return
      }

      if (!feeRate.trim()) {
        onError('Fee rate is required for Dogecoin')
        return
      }
      
      const feeRateBigInt = BigInt(feeRate)
      
      const { psbt: psbtObj, selectedUtxos: utxosForPsbt } = await builder.buildPsbtFromUtxos(
        utxosToUse,
        fromAddress,
        toAddress,
        amountBigInt,
        feeRateBigInt,
        opReturnData.trim() || undefined
      )

      const psbtBase64 = psbtObj.toBase64()
      setPsbt(psbtBase64)
      setPsbtInstance(psbtObj)
      setSelectedUtxosForPsbt(utxosForPsbt)
      setMode('sign')
      onResult({ generated: psbtBase64 })
    } catch (err) {
      onError((err as Error).message || 'Failed to generate PSBT')
    } finally {
      setLoading(false)
    }
  }

  const handleSignPsbt = async (): Promise<void> => {
    const dogeProvider = window.vultisig?.dogecoin
    if (!dogeProvider) {
      onError('Provider not available')
      return
    }

    const connected = await ensureConnection()
    if (!connected) {
      onError('Vultisig wallet not connected. Please connect your wallet to continue.')
      return
    }

    if (!psbt.trim()) {
      onError('PSBT is required')
      return
    }

    setLoading(true)
    
    try {
      const providerObj = dogeProvider as unknown as Record<string, unknown>

      if (!providerObj.signPSBT || typeof providerObj.signPSBT !== 'function') {
        throw new Error('Sign PSBT method not available')
      }

      let currentPsbtInstance = psbtInstance
      if (!currentPsbtInstance) {
        const psbtBuffer = Buffer.from(psbt, 'base64')
        currentPsbtInstance = bitcoin.Psbt.fromBuffer(psbtBuffer, { network: dogeNetwork })
      }

      const psbtBuffer = currentPsbtInstance.toBuffer()
      
      const inputsToSign = currentPsbtInstance.data.inputs.map((_, psbtIndex) => {
        const txInput = currentPsbtInstance.txInputs[psbtIndex]
        const inputHash = Buffer.from(txInput.hash).toString('hex')
        const inputIndex = txInput.index
        
        const utxo = selectedUtxosForPsbt.find(
          (u) => u.hash === inputHash && u.index === inputIndex
        )
        const signingIndex = utxo ? utxo.index : psbtIndex
        
        return {
          address: fromAddress,
          signingIndexes: [signingIndex],
          sigHash: bitcoin.Transaction.SIGHASH_ALL
        }
      })

      const signedPsbtBuffer = await (providerObj.signPSBT as (
        psbt: Uint8Array<ArrayBufferLike>,
        options: { inputsToSign: Array<{ address: string; signingIndexes: number[]; sigHash: number }> },
        finalize?: boolean
      ) => Promise<Buffer>)(psbtBuffer, { inputsToSign }, false)
      
      const signedPsbtBase64 = signedPsbtBuffer.toString('base64')
    
      const signedPsbtInstance = bitcoin.Psbt.fromBuffer(signedPsbtBuffer, { network: dogeNetwork })
      
      for (let i = 0; i < signedPsbtInstance.inputCount; i++) {
        const input = signedPsbtInstance.data.inputs[i]
        if (!input.partialSig || input.partialSig.length === 0) {
          throw new Error(`Input #${i} is not signed. Please sign the PSBT first.`)
        }
      }
      
      setPsbt(signedPsbtBase64)
      setPsbtInstance(signedPsbtInstance)
      
      onResult({ signedPsbt: signedPsbtBase64 })
      setLoading(false)
    } catch (err) {
      onError((err as Error).message || 'Unknown error')
      setLoading(false)
    }
  }

  const totalSelectedValue = Array.from(selectedUtxos).reduce((sum, key) => {
    const utxo = utxos.find((u) => `${u.hash}:${u.index}` === key)
    return sum + (utxo?.value || BigInt(0))
  }, BigInt(0))

  const totalUtxosValue = utxos.reduce((sum, utxo) => sum + utxo.value, BigInt(0))

  const handlePsbtChange = (newPsbt: string): void => {
    setPsbt(newPsbt)
    if (newPsbt.trim() && newPsbt !== psbt) {
      setPsbtInstance(null)
      setSelectedUtxosForPsbt([])
    }
  }

  return (
    <div className="space-y-4">
      <div className="flex gap-2 border-b pb-2">
        <button
          onClick={() => setMode('generate')}
          className={`px-3 py-1 text-xs rounded transition-colors ${
            mode === 'generate'
              ? 'bg-blue-600 text-white'
              : 'bg-gray-100 text-gray-700 hover:bg-gray-200'
          }`}
        >
          Generate PSBT
        </button>
        <button
          onClick={() => setMode('sign')}
          className={`px-3 py-1 text-xs rounded transition-colors ${
            mode === 'sign'
              ? 'bg-blue-600 text-white'
              : 'bg-gray-100 text-gray-700 hover:bg-gray-200'
          }`}
        >
          Sign PSBT
        </button>
      </div>

      {mode === 'generate' ? (
        <GeneratePsbtTab
          fromAddress={fromAddress}
          toAddress={toAddress}
          amount={amount}
          opReturnData={opReturnData}
          utxos={utxos}
          selectedUtxos={selectedUtxos}
          loadingUtxos={loadingUtxos}
          loading={loading}
          totalUtxosValue={totalUtxosValue}
          totalSelectedValue={totalSelectedValue}
          onFromAddressChange={setFromAddress}
          onToAddressChange={setToAddress}
          onAmountChange={setAmount}
          onOpReturnDataChange={setOpReturnData}
          onFetchUtxos={handleFetchUtxos}
          onError={onError}
          onToggleUtxo={handleToggleUtxo}
          onGeneratePsbt={handleGeneratePsbt}
        />
      ) : (
        <SignPsbtTab
          psbt={psbt}
          loading={loading}
          onPsbtChange={handlePsbtChange}
          onSignPsbt={handleSignPsbt}
        />
      )}
    </div>
  )
}

