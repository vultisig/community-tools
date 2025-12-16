import { useState, useEffect, useCallback } from 'react'
import { StargateClient, defaultRegistryTypes } from '@cosmjs/stargate'
import { Registry, makeAuthInfoBytes, encodePubkey } from '@cosmjs/proto-signing'
import { TxRaw } from 'cosmjs-types/cosmos/tx/v1beta1/tx'
import { SignMode } from 'cosmjs-types/cosmos/tx/signing/v1beta1/signing'
import { fromBase64, fromBech32 } from '@cosmjs/encoding'
import { Int53 } from '@cosmjs/math'
import { useWalletConnection } from '../../hooks/useWalletConnection'
import { getExampleDirectMsgs } from './cosmosExamples'
import { getThorchainExampleDirectMsgs } from '../thorchain/thorchainExamples'
import { fetchCosmosAccountInfo, getRpcUrl } from './cosmosUtils'
import { getThorchainRegistryTypes } from '../../lib/messages/types/thorchainRegistry'

interface SignDirectMethodProps {
  provider: unknown
  onResult: (result: unknown) => void
  onError: (error: string) => void
  onAccountUpdate?: (accounts: string[]) => void
}

interface DirectSignDoc {
  chainId: string
  accountNumber: string | number
  bodyBytes: Uint8Array
  authInfoBytes: Uint8Array
}

const COSMOS_CHAIN_IDS = [
  { value: 'cosmoshub-4', label: 'Cosmos Hub (cosmoshub-4)' },
  { value: 'thorchain-1', label: 'THORChain (thorchain-1)' },
]

const COSMOS_FEE_DENOMS = [
  { value: 'uatom', label: 'uatom (ATOM)' },
  { value: 'rune', label: 'rune (RUNE)' },
]

export function SignDirectMethod({ onResult, onError }: SignDirectMethodProps) {
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
    } else if (chainId === 'thorchain-1') {
      setFeeDenom('rune')
    }
  }, [chainId])

  useEffect(() => {
    onResult(undefined)
  }, [chainId, signer, accountNumber, sequence, feeDenom, feeAmount, gas, memo, msgsJson])

  const buildSignDoc = async (provider: unknown): Promise<DirectSignDoc | null> => {
    try {
      const msgs = JSON.parse(msgsJson)
      if (!Array.isArray(msgs)) {
        onError('msgs must be a valid JSON array')
        return null
      }

      // Validate messages have typeUrl and value
      for (const msg of msgs) {
        if (!msg.typeUrl || !msg.value) {
          onError('Each message must have typeUrl and value fields')
          return null
        }
      }

      // Create registry with default types and THORChain types if needed
      const registryTypes = chainId === 'thorchain-1' 
        ? [...defaultRegistryTypes, ...getThorchainRegistryTypes()]
        : defaultRegistryTypes
      
      const registry = new Registry(registryTypes)
      
      // Encode messages to protobuf - messages should be in the format expected by registry
      // For THORChain, convert bech32 addresses to Uint8Array
      const protoMsgs = msgs.map((msg) => {
        let value = msg.value
        
        // Convert addresses for THORChain messages
        if (chainId === 'thorchain-1') {
          value = { ...msg.value }
          
          // Convert addresses for MsgSend
          if (msg.typeUrl === '/types.MsgSend') {
            if (typeof msg.value.fromAddress === 'string') {
              value.fromAddress = fromBech32(msg.value.fromAddress).data
            }
            if (typeof msg.value.toAddress === 'string') {
              value.toAddress = fromBech32(msg.value.toAddress).data
            }
          }
          
          // Convert signer for MsgDeposit
          if (msg.typeUrl === '/types.MsgDeposit' && typeof msg.value.signer === 'string') {
            value.signer = fromBech32(msg.value.signer).data
          }
        }
        
        return {
          typeUrl: msg.typeUrl,
          value: value,
        }
      })

      // Encode TxBody
      const txBodyEncodeObject = {
        typeUrl: '/cosmos.tx.v1beta1.TxBody',
        value: {
          messages: protoMsgs,
          memo: memo,
        },
      }
      const bodyBytes = registry.encode(txBodyEncodeObject)

      // Get pubkey from provider
      const providerObj = provider as unknown as Record<string, unknown>
      if (!providerObj.getKey || typeof providerObj.getKey !== 'function') {
        throw new Error('getKey method is not available')
      }
      const key = await (providerObj.getKey as (chainId: string) => Promise<{
        bech32Address: string
        pubKey: Uint8Array
        algo: string
      }>)(chainId)

      if (!key?.pubKey) {
        throw new Error('Failed to get pubkey from getKey')
      }

      // Convert Uint8Array pubkey to the format expected by encodePubkey
      // Keplr returns pubKey as Uint8Array, but encodePubkey expects { type: string, value: string }
      const pubKeyBase64 = Buffer.from(key.pubKey).toString('base64')
      const pubKeyObj = {
        type: 'tendermint/PubKeySecp256k1',
        value: pubKeyBase64,
      }

      // Create AuthInfoBytes with the correct pubkey
      const gasLimit = Int53.fromString(gas).toNumber()
      const seq = Int53.fromString(sequence).toNumber()
      const pubkey = encodePubkey(pubKeyObj)
      
      const authInfoBytes = makeAuthInfoBytes(
        [{ pubkey, sequence: seq }],
        [{ denom: feeDenom, amount: feeAmount }],
        gasLimit,
        undefined,
        undefined,
        SignMode.SIGN_MODE_DIRECT
      )

      const accountNum = Int53.fromString(accountNumber).toNumber()
      
      const signDoc: DirectSignDoc = {
        chainId: chainId,
        accountNumber: accountNum,
        bodyBytes: bodyBytes,
        authInfoBytes: authInfoBytes,
      }

      return signDoc
    } catch (err) {
      onError(`Error building signDoc: ${(err as Error).message}`)
      return null
    }
  }

  const handleBuildSignDoc = async (): Promise<void> => {
    const keplrProvider = window.vultisig?.keplr
    if (!keplrProvider) {
      onError('Keplr provider not available')
      return
    }

    try {
      const providerObj = keplrProvider as unknown as Record<string, unknown>
      if (!providerObj.enable || typeof providerObj.enable !== 'function') {
        onError('enable method is not available')
        return
      }
      await (providerObj.enable as (chainId: string) => Promise<void>)(chainId)

      const signDoc = await buildSignDoc(keplrProvider)
      if (signDoc) {
        onResult({ signDoc })
      }
    } catch (err) {
      onError((err as Error).message || 'Unknown error building signDoc')
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

    const providerObj = provider as unknown as Record<string, unknown>

    // Enable connection using Keplr's enable method
    if (!providerObj.enable || typeof providerObj.enable !== 'function') {
      throw new Error('enable method is not available')
    }
    await (providerObj.enable as (chainId: string) => Promise<void>)(chainId)

    // Build the signDoc (needs provider to get pubkey)
    const signDoc = await buildSignDoc(provider)
    if (!signDoc) {
      return
    }

    if (!providerObj.signDirect || typeof providerObj.signDirect !== 'function') {
      throw new Error('signDirect method not available')
    }

    // Sign with signDirect
    const signed = await (providerObj.signDirect as (
      chainId: string,
      signer: string,
      signDoc: DirectSignDoc
    ) => Promise<unknown>)(chainId, signer, signDoc)

    const signedObj = signed as {
      signed: DirectSignDoc
      signature: {
        pub_key: { type: string; value: string }
        signature: string
      }
    }

    // Build TxRaw from signed direct transaction
    const bodyBytes = signedObj.signed.bodyBytes
    const authInfoBytes = signedObj.signed.authInfoBytes
    const signatureBytes = fromBase64(signedObj.signature.signature)

    const txRaw = TxRaw.fromPartial({
      bodyBytes,
      authInfoBytes,
      signatures: [signatureBytes],
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

  const handleSignDirect = async (): Promise<void> => {
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

  const handleSignDirectWithKeplr = async (): Promise<void> => {
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

  const handleLoadExample = (example: 'singleSend' | 'multiSend' | 'deposit'): void => {
    // Use connectedAddress if available, otherwise use signer
    const addressToUse = connectedAddress || signer
    
    if (chainId === 'thorchain-1') {
      const exampleMsgs = getThorchainExampleDirectMsgs(addressToUse)
      if (example === 'deposit' && exampleMsgs.deposit) {
        setMsgsJson(JSON.stringify(exampleMsgs.deposit, null, 2))
      } else if (example === 'singleSend') {
        setMsgsJson(JSON.stringify(exampleMsgs.singleSend, null, 2))
      } else if (example === 'multiSend') {
        setMsgsJson(JSON.stringify(exampleMsgs.multiSend, null, 2))
      }
    } else {
      // Don't allow deposit for non-THORChain chains
      if (example === 'deposit') {
        onError('Deposit example is only available for THORChain')
        return
      }
      const exampleMsgs = getExampleDirectMsgs(addressToUse)
      if (example === 'singleSend') {
        setMsgsJson(JSON.stringify(exampleMsgs.singleSend, null, 2))
      } else if (example === 'multiSend') {
        setMsgsJson(JSON.stringify(exampleMsgs.multiSend, null, 2))
      }
    }
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
            {chainId === 'thorchain-1' && (
              <button
                onClick={() => handleLoadExample('deposit')}
                className="text-xs px-2 py-1 bg-gray-100 text-gray-700 rounded hover:bg-gray-200"
              >
                Example: Deposit
              </button>
            )}
          </div>
        </div>
        <textarea
          value={msgsJson}
          onChange={(e) => setMsgsJson(e.target.value)}
          placeholder='[{"typeUrl": "/cosmos.bank.v1beta1.MsgSend", "value": {...}}]'
          className="w-full px-3 py-2 text-xs font-mono border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 resize-y min-h-[120px]"
          rows={6}
        />
        <p className="text-xs text-gray-500 mt-1">
          JSON array with protobuf messages to sign. Each message must have typeUrl and value fields. Use example buttons to load templates.
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
            onClick={handleSignDirect}
            disabled={loading || loadingKeplr}
            className="px-4 py-2 text-sm bg-blue-600 text-white rounded hover:bg-blue-700 disabled:bg-gray-400 disabled:cursor-not-allowed transition-colors"
          >
            {loading ? 'Signing...' : 'Sign with signDirect'}
          </button>
        </div>
        
        <div className="border-t border-gray-200 pt-3">
          <div className="text-xs text-gray-500 mb-2">
            <span className="font-medium">Comparison:</span> Test signing with Keplr extension
          </div>
          <button
            onClick={handleSignDirectWithKeplr}
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
