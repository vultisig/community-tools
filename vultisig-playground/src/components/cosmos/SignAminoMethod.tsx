import { useState, useEffect, useCallback } from 'react'
import { StargateClient, defaultRegistryTypes, createDefaultAminoConverters } from '@cosmjs/stargate'
import { Registry, makeAuthInfoBytes, encodePubkey } from '@cosmjs/proto-signing'
import { TxRaw } from 'cosmjs-types/cosmos/tx/v1beta1/tx'
import { SignMode } from 'cosmjs-types/cosmos/tx/signing/v1beta1/signing'
import { fromBase64 } from '@cosmjs/encoding'
import { Int53 } from '@cosmjs/math'
import { useWalletConnection } from '../../hooks/useWalletConnection'
import { getExampleMsgs } from './cosmosExamples'
import { fetchCosmosAccountInfo, getRpcUrl } from './cosmosUtils'

interface SignAminoMethodProps {
  provider: unknown
  onResult: (result: unknown) => void
  onError: (error: string) => void
  onAccountUpdate?: (accounts: string[]) => void
}

interface AminoSignDoc {
  chain_id: string
  account_number: string
  sequence: string
  fee: {
    amount: Array<{ denom: string; amount: string }>
    gas: string
  }
  msgs: Array<unknown>
  memo: string
}

const COSMOS_CHAIN_IDS = [
  { value: 'cosmoshub-4', label: 'Cosmos Hub (cosmoshub-4)' },
]

const COSMOS_FEE_DENOMS = [
  { value: 'uatom', label: 'uatom (ATOM)' },
]

export function SignAminoMethod({ onResult, onError }: SignAminoMethodProps) {
  const [chainId, setChainId] = useState<string>('cosmoshub-4')
  const [signer, setSigner] = useState<string>('')
  const [accountNumber, setAccountNumber] = useState<string>('0')
  const [sequence, setSequence] = useState<string>('0')
  const [feeDenom, setFeeDenom] = useState<string>('uatom')
  const [feeAmount, setFeeAmount] = useState<string>('1000')
  const [gas, setGas] = useState<string>('200000')
  const [memo, setMemo] = useState<string>('')
  const [msgsJson, setMsgsJson] = useState<string>('[]')
  const [loading, setLoading] = useState<boolean>(false)
  const [loadingKeplr, setLoadingKeplr] = useState<boolean>(false)
  const [loadingAccountInfo, setLoadingAccountInfo] = useState<boolean>(false)

  const { connectedAddress } = useWalletConnection('keplr')

  const fetchAccountInfoFromProvider = useCallback(async (provider: unknown): Promise<void> => {
    setLoadingAccountInfo(true)

    try {
      const accountInfo = await fetchCosmosAccountInfo(provider, chainId)
      setSigner(accountInfo.address)
      setAccountNumber(accountInfo.accountNumber)
      setSequence(accountInfo.sequence)
      setLoadingAccountInfo(false)
    } catch (err) {
      setLoadingAccountInfo(false)
      onError((err as Error).message || 'Unknown error')
    }
  }, [chainId, onError])

  const fetchAccountInfoFromVultisig = useCallback(async (): Promise<void> => {
    const keplrProvider = window.vultisig?.keplr
    if (!keplrProvider) {
      onError('Keplr provider not available')
      return
    }
    await fetchAccountInfoFromProvider(keplrProvider)
  }, [fetchAccountInfoFromProvider, onError])

  const fetchAccountInfoFromKeplr = useCallback(async (): Promise<void> => {
    const keplrProvider = (window as unknown as { keplr?: unknown }).keplr
    if (!keplrProvider) {
      onError('Keplr extension not available')
      return
    }
    await fetchAccountInfoFromProvider(keplrProvider)
  }, [fetchAccountInfoFromProvider, onError])

  useEffect(() => {
    if (connectedAddress) {
      setSigner(connectedAddress)
      // Auto-fetch account info when address is connected
      fetchAccountInfoFromVultisig().catch((err) => {
        console.warn('Auto-fetch account info failed:', err)
      })
    }
  }, [connectedAddress, chainId, fetchAccountInfoFromVultisig])

  useEffect(() => {
    // Auto-update fee denom based on chain ID
    if (chainId === 'cosmoshub-4') {
      setFeeDenom('uatom')
    }
  }, [chainId])

  useEffect(() => {
    onResult(undefined)
  }, [chainId, signer, accountNumber, sequence, feeDenom, feeAmount, gas, memo, msgsJson])

  const buildSignDoc = (): AminoSignDoc | null => {
    try {
      const msgs = JSON.parse(msgsJson)
      if (!Array.isArray(msgs)) {
        onError('msgs must be a valid JSON array')
        return null
      }

      const signDoc: AminoSignDoc = {
        chain_id: chainId,
        account_number: accountNumber,
        sequence: sequence,
        fee: {
          amount: [
            {
              denom: feeDenom,
              amount: feeAmount,
            },
          ],
          gas: gas,
        },
        msgs: msgs,
        memo: memo,
      }

      return signDoc
    } catch (err) {
      onError(`Error parsing msgs JSON: ${(err as Error).message}`)
      return null
    }
  }

  const handleBuildSignDoc = (): void => {
    const signDoc = buildSignDoc()
    if (signDoc) {
      onResult({ signDoc })
    }
  }

  const signAndBroadcast = async (provider: unknown, providerName: string): Promise<void> => {
    if (!chainId.trim()) {
      onError('Chain ID is required')
      return
    }

    if (!signer.trim()) {
      onError('Signer (address) is required')
      return
    }

    // Build the SAME signDoc for both providers
    const signDoc = buildSignDoc()
    if (!signDoc) {
      return
    }

    const providerObj = provider as unknown as Record<string, unknown>

    // Enable connection using Keplr's enable method
    if (!providerObj.enable || typeof providerObj.enable !== 'function') {
      throw new Error('enable method is not available')
    }
    await (providerObj.enable as (chainId: string) => Promise<void>)(chainId)

    if (!providerObj.signAmino || typeof providerObj.signAmino !== 'function') {
      throw new Error('signAmino method not available')
    }

    // Sign with the SAME signDoc
    const signed = await (providerObj.signAmino as (
      chainId: string,
      signer: string,
      signDoc: AminoSignDoc
    ) => Promise<unknown>)(chainId, signer, signDoc)

    // Build StdTx using @cosmjs/amino
    const signedObj = signed as { 
      signed: AminoSignDoc
      signature: {
        pub_key: { type: string; value: string }
        signature: string
      }
    }
    
    // Convert Amino signed transaction to TxRaw protobuf for broadcastTxSync
    const registry = new Registry(defaultRegistryTypes)
    const aminoTypes = createDefaultAminoConverters()
    
    // Convert Amino messages to protobuf
    const protoMsgs = signedObj.signed.msgs.map((msg) => {
      const aminoMsg = msg as { type: string; value: Record<string, unknown> }
      const converterEntry = Object.entries(aminoTypes).find(([_, conv]) => 
        conv && typeof conv === 'object' && 'aminoType' in conv && (conv as { aminoType: string }).aminoType === aminoMsg.type
      )
      if (!converterEntry) {
        throw new Error(`No converter found for message type: ${aminoMsg.type}`)
      }
      const converter = converterEntry[1] as { fromAmino: (amino: unknown) => unknown }
      const protoMsg = converter.fromAmino(aminoMsg.value)
      return {
        typeUrl: converterEntry[0],
        value: protoMsg,
      }
    })
    
    // Encode TxBody
    const txBodyEncodeObject = {
      typeUrl: '/cosmos.tx.v1beta1.TxBody',
      value: {
        messages: protoMsgs,
        memo: signedObj.signed.memo,
      },
    }
    const bodyBytes = registry.encode(txBodyEncodeObject)
    
    // Create AuthInfoBytes
    const gasLimit = Int53.fromString(signedObj.signed.fee.gas).toNumber()
    const sequence = Int53.fromString(signedObj.signed.sequence).toNumber()
    const pubkey = encodePubkey(signedObj.signature.pub_key)
    const authInfoBytes = makeAuthInfoBytes(
      [{ pubkey, sequence }],
      signedObj.signed.fee.amount,
      gasLimit,
      undefined,
      undefined,
      SignMode.SIGN_MODE_LEGACY_AMINO_JSON
    )
    
    // Create TxRaw
    const txRaw = TxRaw.fromPartial({
      bodyBytes,
      authInfoBytes,
      signatures: [fromBase64(signedObj.signature.signature)],
    })
    
    // Serialize TxRaw to bytes
    const txBytes = TxRaw.encode(txRaw).finish()

    // Broadcast using RPC with StargateClient
    const rpcUrl = getRpcUrl(chainId)
    const client = await StargateClient.connect(rpcUrl)
    const txHash = await client.broadcastTxSync(txBytes)
    client.disconnect()

    onResult({ signed, signDoc, broadcast: { txhash: txHash }, provider: providerName })
  }

  const handleSignAmino = async (): Promise<void> => {
    const keplrProvider = window.vultisig?.keplr
    if (!keplrProvider) {
      onError('Keplr provider not available')
      return
    }

    setLoading(true)
    try {
      await signAndBroadcast(keplrProvider, 'vultisig')
    } catch (err) {
      onError((err as Error).message || 'Unknown error signing')
    } finally {
      setLoading(false)
    }
  }

  const handleSignAminoWithKeplr = async (): Promise<void> => {
    const keplrProvider = (window as unknown as { keplr?: unknown }).keplr
    if (!keplrProvider) {
      onError('Keplr extension not available')
      return
    }

    setLoadingKeplr(true)
    try {
      await signAndBroadcast(keplrProvider, 'keplr')
    } catch (err) {
      onError(`Keplr: ${(err as Error).message || 'Unknown error signing'}`)
    } finally {
      setLoadingKeplr(false)
    }
  }

  const handleLoadExample = (example: 'singleSend' | 'multiSend'): void => {
    const exampleMsgs = getExampleMsgs(signer)
    setMsgsJson(JSON.stringify(exampleMsgs[example], null, 2))
  }

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div>
          <label className="block text-xs font-medium text-gray-700 mb-1">
            Chain ID <span className="text-red-500">*</span>
          </label>
          <select
            value={chainId}
            onChange={(e) => setChainId(e.target.value)}
            className="w-full px-3 py-2 text-xs font-mono border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 bg-white"
          >
            {COSMOS_CHAIN_IDS.map((chain) => (
              <option key={chain.value} value={chain.value}>
                {chain.label}
              </option>
            ))}
          </select>
        </div>

        <div>
          <label className="block text-xs font-medium text-gray-700 mb-2">
            Get Address <span className="text-red-500">*</span>
          </label>
          <div className="flex gap-2">
            <button
              onClick={fetchAccountInfoFromVultisig}
              disabled={loadingAccountInfo}
              className="flex-1 px-3 py-2 text-xs bg-blue-600 text-white rounded hover:bg-blue-700 disabled:bg-gray-400 disabled:cursor-not-allowed transition-colors whitespace-nowrap"
              title="Fetch address and account info from Vultisig"
            >
              {loadingAccountInfo ? 'Loading...' : 'Fetch from Vultisig'}
            </button>
            <button
              onClick={fetchAccountInfoFromKeplr}
              disabled={loadingAccountInfo || !(window as unknown as { keplr?: unknown }).keplr}
              className="flex-1 px-3 py-2 text-xs bg-purple-600 text-white rounded hover:bg-purple-700 disabled:bg-gray-400 disabled:cursor-not-allowed transition-colors whitespace-nowrap"
              title="Fetch address and account info from Keplr extension"
            >
              {loadingAccountInfo ? 'Loading...' : 'Fetch from Keplr'}
            </button>
          </div>
          {signer && (
            <p className="text-xs text-gray-500 mt-1 font-mono">
              Address: {signer}
            </p>
          )}
        </div>

        <div>
          <label className="block text-xs font-medium text-gray-700 mb-1">
            Fee Denom
          </label>
          <select
            value={feeDenom}
            onChange={(e) => setFeeDenom(e.target.value)}
            className="w-full px-3 py-2 text-xs font-mono border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 bg-white"
          >
            {COSMOS_FEE_DENOMS.map((denom) => (
              <option key={denom.value} value={denom.value}>
                {denom.label}
              </option>
            ))}
          </select>
        </div>

        <div>
          <label className="block text-xs font-medium text-gray-700 mb-1">
            Fee Amount
          </label>
          <input
            type="text"
            value={feeAmount}
            onChange={(e) => setFeeAmount(e.target.value)}
            placeholder="1000"
            className="w-full px-3 py-2 text-xs font-mono border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
          />
        </div>

        <div>
          <label className="block text-xs font-medium text-gray-700 mb-1">
            Gas
          </label>
          <input
            type="text"
            value={gas}
            onChange={(e) => setGas(e.target.value)}
            placeholder="200000"
            className="w-full px-3 py-2 text-xs font-mono border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
          />
        </div>

        <div>
          <label className="block text-xs font-medium text-gray-700 mb-1">
            Memo
          </label>
          <input
            type="text"
            value={memo}
            onChange={(e) => setMemo(e.target.value)}
            placeholder="Optional"
            className="w-full px-3 py-2 text-xs font-mono border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
          />
        </div>
      </div>

      <div>
        <div className="flex items-center justify-between mb-2">
          <label className="block text-xs font-medium text-gray-700">
            Messages (msgs) - JSON Array <span className="text-red-500">*</span>
          </label>
          <div className="flex gap-2">
            <button
              onClick={() => handleLoadExample('singleSend')}
              className="text-xs px-2 py-1 bg-gray-100 text-gray-700 rounded hover:bg-gray-200"
            >
              Example: Single Message
            </button>
            <button
              onClick={() => handleLoadExample('multiSend')}
              className="text-xs px-2 py-1 bg-gray-100 text-gray-700 rounded hover:bg-gray-200"
            >
              Example: Multi-Send
            </button>
          </div>
        </div>
        <textarea
          value={msgsJson}
          onChange={(e) => setMsgsJson(e.target.value)}
          placeholder='[{"type": "cosmos-sdk/MsgSend", "value": {...}}]'
          className="w-full px-3 py-2 text-xs font-mono border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 resize-y min-h-[120px]"
          rows={6}
        />
        <p className="text-xs text-gray-500 mt-1">
          JSON array with messages to sign. Use example buttons to load templates.
        </p>
      </div>

      <div className="space-y-3">
        <div className="flex gap-2">
          <button
            onClick={handleBuildSignDoc}
            className="px-4 py-2 text-sm bg-gray-600 text-white rounded hover:bg-gray-700 transition-colors"
          >
            Build SignDoc
          </button>
          <button
            onClick={handleSignAmino}
            disabled={loading || loadingKeplr}
            className="px-4 py-2 text-sm bg-blue-600 text-white rounded hover:bg-blue-700 disabled:bg-gray-400 disabled:cursor-not-allowed transition-colors"
          >
            {loading ? 'Signing...' : 'Sign with signAmino'}
          </button>
        </div>
        
        <div className="border-t border-gray-200 pt-3">
          <div className="text-xs text-gray-500 mb-2">
            <span className="font-medium">Comparison:</span> Test signing with Keplr extension
          </div>
          <button
            onClick={handleSignAminoWithKeplr}
            disabled={loadingKeplr || loading || !(window as unknown as { keplr?: unknown }).keplr}
            className="w-full px-3 py-2 text-xs bg-purple-50 border border-purple-200 text-purple-700 rounded hover:bg-purple-100 disabled:bg-gray-50 disabled:text-gray-400 disabled:border-gray-200 disabled:cursor-not-allowed transition-colors"
            title="Sign and Broadcast with Keplr extension (for comparison)"
          >
            {loadingKeplr || loading 
              ? (loadingKeplr ? 'Signing with Keplr...' : 'Broadcasting...') 
              : 'Sign with Keplr'}
          </button>
        </div>
      </div>
    </div>
  )
}

