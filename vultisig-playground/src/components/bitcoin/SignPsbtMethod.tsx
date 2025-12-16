import { useState, useEffect } from 'react'
import { Buffer } from 'buffer'
import * as bitcoin from '@shapeshiftoss/bitcoinjs-lib'
import { UtxoContext } from '../../lib/tx/btc/UtxoContext'
import { UtxoQueryClient, Utxo, UtxoWithHex } from '../../lib/tx/btc/UtxoQueryClient'
import { PsbtBuilder } from '../../lib/tx/btc/psbtBuilder'
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
  const [loadingPhantom, setLoadingPhantom] = useState<boolean>(false)
  const [broadcasting, setBroadcasting] = useState<boolean>(false)
  const [txid, setTxid] = useState<string>('')

  const [fromAddress, setFromAddress] = useState<string>('bc1qf6sqcalymxg79z76sm2700m0c0f4fazlw7j0xp')
  const [toAddress, setToAddress] = useState<string>('bc1qf6sqcalymxg79z76sm2700m0c0f4fazlw7j0xp')
  const [amount, setAmount] = useState<string>('')
  const [opReturnData, setOpReturnData] = useState<string>('')
  
  const [utxos, setUtxos] = useState<UtxoWithHex[]>([])
  const [selectedUtxos, setSelectedUtxos] = useState<Set<string>>(new Set())
  const [loadingUtxos, setLoadingUtxos] = useState<boolean>(false)
  
  const { connectedAddress, ensureConnection } = useWalletConnection('bitcoin')

  useEffect(() => {
    if (connectedAddress) {
      setFromAddress(connectedAddress)
    }
  }, [connectedAddress])

  useEffect(() => {
    setTxid('')
    setBroadcasting(false)
    setLoading(false)
    setLoadingPhantom(false)
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
      const utxoClient = new UtxoQueryClient('BTC', fromAddress)
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
      const builder = new PsbtBuilder()
      
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

      let feeRateBigInt: bigint
      if (feeRate.trim()) {
        feeRateBigInt = BigInt(feeRate)
      } else {
        feeRateBigInt = await UtxoContext.fetchRecommendedFeeRate()
      }
      
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

  const handleSignPsbt = async (providerName: 'vultisig' | 'phantom'): Promise<void> => {
    const provider = providerName === 'vultisig' 
      ? window.vultisig?.bitcoin 
      : (window as unknown as { phantom?: { bitcoin?: unknown } }).phantom?.bitcoin
    const providerDisplayName = providerName === 'vultisig' ? 'Vultisig' : 'Phantom'
    
    if (!provider) {
      onError(providerName === 'vultisig' ? 'Provider not available' : 'Phantom extension not detected')
      return
    }

    if (providerName === 'vultisig') {
      const connected = await ensureConnection()
      if (!connected) {
        onError('Vultisig wallet not connected. Please connect your wallet to continue.')
        return
      }
    }

    if (!psbt.trim()) {
      onError('PSBT is required')
      return
    }

    const setLoadingState = providerName === 'vultisig' ? setLoading : setLoadingPhantom
    setLoadingState(true)
    
    try {
      const providerObj = provider as unknown as Record<string, unknown>

      if (!providerObj.signPSBT || typeof providerObj.signPSBT !== 'function') {
        throw new Error(`${providerDisplayName} Sign PSBT method not available`)
      }

      let currentPsbtInstance = psbtInstance
      if (!currentPsbtInstance) {
        const psbtBuffer = Buffer.from(psbt, 'base64')
        currentPsbtInstance = bitcoin.Psbt.fromBuffer(psbtBuffer)
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
    
      const signedPsbtInstance = bitcoin.Psbt.fromBuffer(signedPsbtBuffer, { network: bitcoin.networks.bitcoin })
      
      for (let i = 0; i < signedPsbtInstance.inputCount; i++) {
        const input = signedPsbtInstance.data.inputs[i]
        if (!input.partialSig || input.partialSig.length === 0) {
          throw new Error(`Input #${i} is not signed. Please sign the PSBT first.`)
        }
      }
      
      setPsbt(signedPsbtBase64)
      setPsbtInstance(signedPsbtInstance)
      
      setBroadcasting(true)
      try {
        const finalizedPsbt = bitcoin.Psbt.fromBuffer(signedPsbtInstance.toBuffer(), { network: bitcoin.networks.bitcoin })
        
        try {
          finalizedPsbt.finalizeAllInputs()
        } catch (finalizeError) {
          for (let i = 0; i < finalizedPsbt.inputCount; i++) {
            try {
              finalizedPsbt.finalizeInput(i)
            } catch (inputError) {
              throw new Error(`Cannot finalize input #${i}: ${(inputError as Error).message}. Make sure the PSBT is fully signed.`)
            }
          }
        }

        const tx = finalizedPsbt.extractTransaction()
        const txHex = tx.toHex()

        await UtxoContext.broadcastTransaction(txHex)

        const txid = tx.getId()
        setTxid(txid)
        
        const resultKey = providerName === 'vultisig' ? 'signedPsbt' : 'signedPsbtPhantom'
        const result = providerName === 'vultisig' 
          ? { [resultKey]: signedPsbtBase64, broadcasted: true, txid }
          : { [resultKey]: signedPsbtBase64, provider: 'phantom', broadcasted: true, txid }
        onResult(result)
      } catch (broadcastErr) {
        const resultKey = providerName === 'vultisig' ? 'signedPsbt' : 'signedPsbtPhantom'
        const result = providerName === 'vultisig'
          ? { [resultKey]: signedPsbtBase64 }
          : { [resultKey]: signedPsbtBase64, provider: 'phantom' }
        onResult(result)
        onError(`${providerDisplayName} broadcast failed: ${(broadcastErr as Error).message || 'Unknown error'}`)
      } finally {
        setBroadcasting(false)
        setLoadingState(false)
      }
    } catch (err) {
      onError(`${providerDisplayName}: ${(err as Error).message || 'Unknown error'}`)
      setLoadingState(false)
      setBroadcasting(false)
    }
  }

  const handleSignPsbtWithPhantom = async (): Promise<void> => {
    return handleSignPsbt('phantom')
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
          loadingPhantom={loadingPhantom}
          broadcasting={broadcasting}
          txid={txid}
          onPsbtChange={handlePsbtChange}
          onSignPsbt={() => handleSignPsbt('vultisig')}
          onSignPsbtWithPhantom={handleSignPsbtWithPhantom}
        />
      )}
    </div>
  )
}
