import { useState, useEffect, useCallback } from 'react'
import { HiRefresh } from 'react-icons/hi'
import { useParams } from 'react-router-dom'
import { useProviderMethods } from '../hooks/useProviderMethods'
import { getMethodComponent } from '../components/methodMapping'
import { getProviderDisplayName } from '../config/providerNames'

interface MethodResult {
  [methodName: string]: {
    result?: unknown
    error?: string
    loading: boolean
  }
}

function ProviderPlayground() {
  const { chain, provider } = useParams<{ chain: string; provider: string }>()
  const [error, setError] = useState<string | null>(null)
  const [methodResults, setMethodResults] = useState<MethodResult>({})
  const [selectedMethod, setSelectedMethod] = useState<string>('')
  const providerMethods = useProviderMethods(provider || '')
  
  const getProviderInstance = (): unknown | null => {
    if (!provider || !window.vultisig) return null
    return (window.vultisig as Record<string, unknown>)[provider] || null
  }

  useEffect(() => {
    const providerInstance = getProviderInstance()
    if (providerInstance) {
      setError(null)
    } else if (window.vultisig) {
      setError(`Vultisig extension detected, but ${provider} provider is not available.`)
    } else {
      setError('Vultisig extension not detected. Please install the extension.')
    }
    setMethodResults({})
    setSelectedMethod('')
  }, [chain, provider])

  useEffect(() => {
    if (providerMethods.length > 0 && !selectedMethod) {
      setSelectedMethod(providerMethods[0])
    }
  }, [providerMethods, selectedMethod])

  const refreshAccounts = (): void => {
    setError(null)
    setMethodResults({})
    if (providerMethods.length > 0) {
      setSelectedMethod(providerMethods[0])
    }
  }

  const createHandlers = useCallback((methodName: string) => {
    return {
      handleResult: (result: unknown): void => {
        setMethodResults((prev) => ({
          ...prev,
          [methodName]: { result, loading: false }
        }))
      },
      handleError: (error: string): void => {
        setMethodResults((prev) => ({
          ...prev,
          [methodName]: { error, loading: false }
        }))
      }
    }
  }, [])

  const providerInstance = getProviderInstance()
  const chainName = chain ? chain.charAt(0).toUpperCase() + chain.slice(1) : ''
  const providerName = provider ? getProviderDisplayName(provider) : ''

  return (
    <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
      <div className="flex items-center justify-between mb-4">
        <h2 className="text-xl font-semibold text-gray-900">
          {chainName} - {providerName} Playground
        </h2>
        {providerInstance !== null && (
          <button
            onClick={refreshAccounts}
            className="px-3 py-2 border border-gray-300 text-gray-700 rounded-lg hover:bg-gray-50 hover:border-gray-400 transition-colors flex items-center justify-center"
            title="Refresh extension information"
          >
            <HiRefresh className="w-5 h-5" />
          </button>
        )}
      </div>

      {error && (
        <div className="bg-red-50 border border-red-200 rounded-lg p-4 mb-4">
          <p className="text-red-800">{error}</p>
        </div>
      )}

      <div className="space-y-4">
        {providerInstance !== null && (
          <div className="space-y-4">
            {providerMethods.length > 0 && (
              <div className="bg-gray-50 border border-gray-200 rounded-lg p-4">
                <h3 className="text-sm font-semibold text-gray-900 mb-4">
                  Available Methods for {providerName} Provider
                </h3>
                <div className="border-b border-gray-200 mb-4">
                  <nav className="flex space-x-1 overflow-x-auto" aria-label="Method tabs">
                    {providerMethods.map((method) => {
                      const methodResult = methodResults[method]
                      const hasResults = methodResult && (methodResult.error || methodResult.result !== undefined)
                      const isActive = selectedMethod === method
                      return (
                        <button
                          key={method}
                          onClick={() => setSelectedMethod(method)}
                          className={`
                            px-4 py-2 text-xs font-medium rounded-t-lg transition-colors whitespace-nowrap
                            ${isActive
                              ? 'bg-white text-blue-600 border-b-2 border-blue-600'
                              : 'text-gray-600 hover:text-gray-900 hover:bg-gray-100'
                            }
                          `}
                        >
                          {method}
                          {hasResults && (
                            <span className={`ml-2 px-1.5 py-0.5 rounded text-xs ${
                              methodResult?.error 
                                ? 'bg-red-100 text-red-700' 
                                : 'bg-green-100 text-green-700'
                            }`}>
                              {methodResult?.error ? '!' : '✓'}
                            </span>
                          )}
                        </button>
                      )
                    })}
                  </nav>
                </div>

                {selectedMethod && (
                  <div className="bg-white border border-gray-200 rounded-lg p-4">
                    <div className="mb-3">
                      <code className="text-sm font-mono text-gray-900 font-semibold">
                        {selectedMethod}
                      </code>
                    </div>
                    
                    {(() => {
                      const methodResult = methodResults[selectedMethod]
                      const MethodComponent = getMethodComponent(chain || '', selectedMethod)
                      const { handleResult, handleError } = createHandlers(selectedMethod)

                      return (
                        <>
                          {MethodComponent ? (
                            <MethodComponent
                              provider={providerInstance}
                              onResult={handleResult}
                              onError={handleError}
                            />
                          ) : (
                            <div className="bg-yellow-50 border border-yellow-200 rounded-md p-3">
                              <p className="text-xs text-yellow-800">
                                No implementation available to test this method
                              </p>
                            </div>
                          )}

                          {methodResult && (methodResult.error || methodResult.result !== undefined) && (
                            <div className="mt-3 pt-3 border-t border-gray-200">
                              {methodResult.error && (
                                <div className="text-xs text-red-600 font-mono break-all">
                                  <span className="font-semibold">Error:</span> {methodResult.error}
                                </div>
                              )}
                              {methodResult.result !== undefined && (
                                <div className="text-xs text-gray-700 font-mono break-all">
                                  <span className="font-semibold">Result:</span>
                                  <pre className="mt-1 p-2 bg-gray-50 rounded overflow-auto max-h-60">
                                    {JSON.stringify(methodResult.result, null, 2)}
                                  </pre>
                                </div>
                              )}
                            </div>
                          )}
                        </>
                      )
                    })()}
                  </div>
                )}
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  )
}

export default ProviderPlayground

