import { useState, useEffect, useCallback } from 'react'

interface UseWalletConnectionResult {
  isConnected: boolean
  connectedAddress: string | null
  isLoading: boolean
  ensureConnection: () => Promise<boolean>
}

export function useWalletConnection(chain: 'bitcoin' | string = 'bitcoin'): UseWalletConnectionResult {
  const [isConnected, setIsConnected] = useState<boolean>(false)
  const [connectedAddress, setConnectedAddress] = useState<string | null>(null)
  const [isLoading, setIsLoading] = useState<boolean>(true)

  const checkConnection = useCallback(async (): Promise<void> => {
    if (!window.vultisig) {
      setIsConnected(false)
      setConnectedAddress(null)
      setIsLoading(false)
      return
    }

    const provider = (window.vultisig as Record<string, unknown>)[chain]
    
    if (!provider) {
      setIsConnected(false)
      setConnectedAddress(null)
      setIsLoading(false)
      return
    }

    try {
      const providerObj = provider as unknown as Record<string, unknown>
      if (providerObj.request) {
        const accounts = await (providerObj.request as (params: { method: string }) => Promise<string[]>)({
          method: 'get_accounts'
        })
        if (accounts && accounts.length > 0) {
          setIsConnected(true)
          setConnectedAddress(accounts[0])
        } else {
          setIsConnected(false)
          setConnectedAddress(null)
        }
      } else {
        setIsConnected(false)
        setConnectedAddress(null)
      }
    } catch (err) {
      console.error(`Failed to check wallet connection for ${chain}`, err)
      setIsConnected(false)
      setConnectedAddress(null)
    } finally {
      setIsLoading(false)
    }
  }, [chain])

  useEffect(() => {
    setIsLoading(true)
    checkConnection()
  }, [checkConnection])

  const ensureConnection = useCallback(async (): Promise<boolean> => {
    if (!window.vultisig) {
      return false
    }

    const provider = (window.vultisig as Record<string, unknown>)[chain]
    
    if (!provider) {
      return false
    }

    try {
      const providerObj = provider as unknown as Record<string, unknown>
      if (!providerObj.request) {
        return false
      }

      const accounts = await (providerObj.request as (params: { method: string }) => Promise<string[]>)({
        method: 'get_accounts'
      })
      
      if (accounts && accounts.length > 0) {
        setIsConnected(true)
        setConnectedAddress(accounts[0])
        return true
      }

      const requestedAccounts = await (providerObj.request as (params: { method: string }) => Promise<string[]>)({
        method: 'request_accounts'
      })
      
      if (requestedAccounts && requestedAccounts.length > 0) {
        setIsConnected(true)
        setConnectedAddress(requestedAccounts[0])
        return true
      }

      setIsConnected(false)
      setConnectedAddress(null)
      return false
    } catch (err) {
      console.error(`Failed to ensure wallet connection for ${chain}`, err)
      setIsConnected(false)
      setConnectedAddress(null)
      return false
    }
  }, [chain])

  return { isConnected, connectedAddress, isLoading, ensureConnection }
}

