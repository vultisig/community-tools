import { useState, useCallback } from 'react'
import type {
  PolkadotInjectedAccount,
  PolkadotSignerPayloadJSON,
  PolkadotSignerPayloadRaw,
  PolkadotSignerResult,
} from '../../types/vultisig'

interface InjectedWeb3PlaygroundProps {
  onResult: (result: unknown) => void
  onError: (error: string) => void
}

type EnabledProvider = Awaited<ReturnType<NonNullable<NonNullable<Window['injectedWeb3']>[string]>['enable']>>

const defaultSignPayload: PolkadotSignerPayloadJSON = {
  address: '',
  blockHash: '0x0000000000000000000000000000000000000000000000000000000000000000',
  blockNumber: '0x00000000',
  era: '0x0000',
  genesisHash: '0x91b171bb158e2d3848fa23a9f1c25182fb8e20313b2c1eb49219da7a70ce90c3',
  method: '0x0000',
  nonce: '0x00000000',
  specVersion: '0x00000000',
  tip: '0x00000000000000000000000000000000',
  transactionVersion: '0x00000000',
  signedExtensions: [],
  version: 4,
}

const defaultSignRaw: PolkadotSignerPayloadRaw = {
  address: '',
  data: '0x48656c6c6f20566f6c746973696721',
  type: 'bytes',
}

function InjectedWeb3Playground({ onResult, onError }: InjectedWeb3PlaygroundProps) {
  const [enabledProvider, setEnabledProvider] = useState<EnabledProvider | null>(null)
  const [accounts, setAccounts] = useState<PolkadotInjectedAccount[]>([])
  const [loading, setLoading] = useState<Record<string, boolean>>({})
  const [results, setResults] = useState<Record<string, unknown>>({})
  const [signPayloadInput, setSignPayloadInput] = useState(JSON.stringify(defaultSignPayload, null, 2))
  const [signRawInput, setSignRawInput] = useState(JSON.stringify(defaultSignRaw, null, 2))

  const setMethodLoading = (method: string, value: boolean) => {
    setLoading(prev => ({ ...prev, [method]: value }))
  }

  const setMethodResult = (method: string, result: unknown) => {
    setResults(prev => ({ ...prev, [method]: result }))
  }

  const handleEnable = useCallback(async () => {
    setMethodLoading('enable', true)
    try {
      const injectedWeb3 = window.injectedWeb3
      if (!injectedWeb3?.vultisig) {
        onError('window.injectedWeb3.vultisig not found. Is the Vultisig extension installed?')
        return
      }
      const provider = await injectedWeb3.vultisig.enable('vultisig-playground')
      setEnabledProvider(provider)
      setMethodResult('enable', { success: true, hasAccounts: !!provider.accounts, hasSigner: !!provider.signer })
      onResult({ enabled: true, accounts: !!provider.accounts, signer: !!provider.signer })
    } catch (err) {
      onError((err as Error).message || 'Failed to enable')
    } finally {
      setMethodLoading('enable', false)
    }
  }, [onResult, onError])

  const handleGetAccounts = useCallback(async () => {
    if (!enabledProvider) return
    setMethodLoading('accounts.get', true)
    try {
      const accs = await enabledProvider.accounts.get()
      setAccounts(accs)
      setMethodResult('accounts.get', accs)
      onResult(accs)
    } catch (err) {
      onError((err as Error).message || 'Failed to get accounts')
    } finally {
      setMethodLoading('accounts.get', false)
    }
  }, [enabledProvider, onResult, onError])

  const handleSubscribeAccounts = useCallback(() => {
    if (!enabledProvider) return
    setMethodLoading('accounts.subscribe', true)
    try {
      const unsub = enabledProvider.accounts.subscribe((accs: PolkadotInjectedAccount[]) => {
        setAccounts(accs)
        setMethodResult('accounts.subscribe', accs)
        onResult({ subscriptionUpdate: accs })
      })
      setMethodResult('accounts.subscribe', { subscribed: true, message: 'Listening for account changes...' })
      onResult({ subscribed: true, unsubscribe: typeof unsub === 'function' })
    } catch (err) {
      onError((err as Error).message || 'Failed to subscribe')
    } finally {
      setMethodLoading('accounts.subscribe', false)
    }
  }, [enabledProvider, onResult, onError])

  const handleSignPayload = useCallback(async () => {
    if (!enabledProvider) return
    setMethodLoading('signer.signPayload', true)
    try {
      let payload: PolkadotSignerPayloadJSON
      try {
        payload = JSON.parse(signPayloadInput)
      } catch {
        onError('Invalid JSON for signPayload')
        setMethodLoading('signer.signPayload', false)
        return
      }
      if (!payload.address && accounts.length > 0) {
        payload.address = accounts[0].address
      }
      const result: PolkadotSignerResult = await enabledProvider.signer.signPayload(payload)
      setMethodResult('signer.signPayload', result)
      onResult(result)
    } catch (err) {
      onError((err as Error).message || 'Failed to sign payload')
    } finally {
      setMethodLoading('signer.signPayload', false)
    }
  }, [enabledProvider, signPayloadInput, accounts, onResult, onError])

  const handleSignRaw = useCallback(async () => {
    if (!enabledProvider) return
    setMethodLoading('signer.signRaw', true)
    try {
      let payload: PolkadotSignerPayloadRaw
      try {
        payload = JSON.parse(signRawInput)
      } catch {
        onError('Invalid JSON for signRaw')
        setMethodLoading('signer.signRaw', false)
        return
      }
      if (!payload.address && accounts.length > 0) {
        payload.address = accounts[0].address
      }
      const result: PolkadotSignerResult = await enabledProvider.signer.signRaw(payload)
      setMethodResult('signer.signRaw', result)
      onResult(result)
    } catch (err) {
      onError((err as Error).message || 'Failed to sign raw')
    } finally {
      setMethodLoading('signer.signRaw', false)
    }
  }, [enabledProvider, signRawInput, accounts, onResult, onError])

  const renderResult = (key: string) => {
    const result = results[key]
    if (result === undefined) return null
    return (
      <pre className="mt-2 p-2 bg-gray-50 rounded text-xs font-mono overflow-auto max-h-40">
        {JSON.stringify(result, null, 2)}
      </pre>
    )
  }

  return (
    <div className="space-y-4">
      {/* Step 1: Enable */}
      <div className="border border-gray-200 rounded-lg p-4">
        <h4 className="text-sm font-semibold text-gray-900 mb-2">1. enable(origin)</h4>
        <p className="text-xs text-gray-500 mb-3">
          Calls <code>window.injectedWeb3.vultisig.enable('vultisig-playground')</code> to get accounts and signer.
        </p>
        <button
          onClick={handleEnable}
          disabled={loading['enable']}
          className="w-full px-4 py-2 text-sm bg-blue-600 text-white rounded hover:bg-blue-700 disabled:bg-gray-400 disabled:cursor-not-allowed transition-colors"
        >
          {loading['enable'] ? 'Enabling...' : enabledProvider ? 'Re-enable' : 'Enable'}
        </button>
        {renderResult('enable')}
      </div>

      {/* Step 2: Accounts */}
      {enabledProvider && (
        <div className="border border-gray-200 rounded-lg p-4">
          <h4 className="text-sm font-semibold text-gray-900 mb-2">2. accounts</h4>

          <div className="space-y-3">
            <div>
              <p className="text-xs text-gray-500 mb-2">
                <code>accounts.get()</code> - Retrieve available accounts
              </p>
              <button
                onClick={handleGetAccounts}
                disabled={loading['accounts.get']}
                className="w-full px-4 py-2 text-sm bg-green-600 text-white rounded hover:bg-green-700 disabled:bg-gray-400 disabled:cursor-not-allowed transition-colors"
              >
                {loading['accounts.get'] ? 'Getting...' : 'Get Accounts'}
              </button>
              {renderResult('accounts.get')}
            </div>

            <div>
              <p className="text-xs text-gray-500 mb-2">
                <code>accounts.subscribe(cb)</code> - Subscribe to account changes
              </p>
              <button
                onClick={handleSubscribeAccounts}
                disabled={loading['accounts.subscribe']}
                className="w-full px-4 py-2 text-sm bg-green-600 text-white rounded hover:bg-green-700 disabled:bg-gray-400 disabled:cursor-not-allowed transition-colors"
              >
                {loading['accounts.subscribe'] ? 'Subscribing...' : 'Subscribe to Accounts'}
              </button>
              {renderResult('accounts.subscribe')}
            </div>
          </div>

          {accounts.length > 0 && (
            <div className="mt-3 p-2 bg-blue-50 rounded">
              <p className="text-xs font-semibold text-blue-800 mb-1">Connected Accounts:</p>
              {accounts.map((acc, i) => (
                <div key={i} className="text-xs font-mono text-blue-700 break-all">
                  {acc.name && <span className="font-semibold">{acc.name}: </span>}
                  {acc.address}
                  {acc.type && <span className="text-blue-500 ml-1">({acc.type})</span>}
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Step 3: Signer */}
      {enabledProvider && (
        <div className="border border-gray-200 rounded-lg p-4">
          <h4 className="text-sm font-semibold text-gray-900 mb-2">3. signer</h4>

          <div className="space-y-4">
            {/* signPayload */}
            <div>
              <p className="text-xs text-gray-500 mb-2">
                <code>signer.signPayload(payload)</code> - Sign an extrinsic payload
              </p>
              <textarea
                value={signPayloadInput}
                onChange={(e) => setSignPayloadInput(e.target.value)}
                className="w-full px-3 py-2 text-xs font-mono border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 resize-y min-h-[120px]"
                rows={8}
              />
              <button
                onClick={handleSignPayload}
                disabled={loading['signer.signPayload']}
                className="w-full mt-2 px-4 py-2 text-sm bg-purple-600 text-white rounded hover:bg-purple-700 disabled:bg-gray-400 disabled:cursor-not-allowed transition-colors"
              >
                {loading['signer.signPayload'] ? 'Signing...' : 'Sign Payload'}
              </button>
              {renderResult('signer.signPayload')}
            </div>

            {/* signRaw */}
            <div>
              <p className="text-xs text-gray-500 mb-2">
                <code>signer.signRaw(payload)</code> - Sign raw bytes
              </p>
              <textarea
                value={signRawInput}
                onChange={(e) => setSignRawInput(e.target.value)}
                className="w-full px-3 py-2 text-xs font-mono border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 resize-y min-h-[80px]"
                rows={5}
              />
              <button
                onClick={handleSignRaw}
                disabled={loading['signer.signRaw']}
                className="w-full mt-2 px-4 py-2 text-sm bg-purple-600 text-white rounded hover:bg-purple-700 disabled:bg-gray-400 disabled:cursor-not-allowed transition-colors"
              >
                {loading['signer.signRaw'] ? 'Signing...' : 'Sign Raw'}
              </button>
              {renderResult('signer.signRaw')}
            </div>
          </div>
        </div>
      )}

      {!enabledProvider && (
        <div className="bg-yellow-50 border border-yellow-200 rounded-md p-3">
          <p className="text-xs text-yellow-800">
            Click "Enable" first to access accounts and signer methods.
          </p>
        </div>
      )}
    </div>
  )
}

export default InjectedWeb3Playground
