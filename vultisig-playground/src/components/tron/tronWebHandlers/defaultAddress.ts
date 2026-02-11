import type { TronWeb } from 'tronweb'
import type { TronWebExecuteContext } from './types'

export async function executeDefaultAddress(ctx: TronWebExecuteContext): Promise<string> {
  const { tronWeb, tronProvider, useTronLink } = ctx

  let currentTronWeb = tronWeb
  let defaultAddress = tronWeb?.defaultAddress

  if (useTronLink && !defaultAddress?.base58) {
    const providerObj = tronProvider as {
      request?: (params: { method: string; params?: unknown[] }) => Promise<unknown>
    }
    if (providerObj.request) {
      await providerObj.request({ method: 'tron_requestAccounts', params: [] })
      const w = window as unknown as { tronWeb?: TronWeb; tronLink?: { tronWeb?: TronWeb } }
      currentTronWeb = (w.tronWeb || w.tronLink?.tronWeb) || null
      if (currentTronWeb) {
        defaultAddress = currentTronWeb.defaultAddress
      }
    }
  }

  if (!defaultAddress?.base58) {
    throw new Error(
      'Please use the "request" method first to connect your Tron account. defaultAddress.base58 is not available in tronWeb.'
    )
  }

  return defaultAddress.base58
}
