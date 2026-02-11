import type { TronWeb } from 'tronweb'

export type TronWebMethodId = 'defaultAddress' | 'signMessage' | 'signMessageV2' | 'signAndBroadcast'

export interface TronWebExecuteContext {
  tronWeb: TronWeb | null
  tronProvider: unknown
  useTronLink: boolean
  messageToSign?: string
  transactionJson?: string
  /** Solo para signMessage: true = con header, false = sin header */
  signMessageUseTronHeader?: boolean
}
