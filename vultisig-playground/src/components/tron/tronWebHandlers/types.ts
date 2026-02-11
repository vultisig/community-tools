import type { TronWeb } from 'tronweb'

export type TronWebMethodId = 'defaultAddress' | 'signMessage' | 'signMessageV2' | 'signAndBroadcast'

export interface TronWebExecuteContext {
  tronWeb: TronWeb | null
  tronProvider: unknown
  useTronLink: boolean
  messageToSign?: string
  transactionJson?: string
  /** Only for signMessage: true = with header, false = without header */
  signMessageUseTronHeader?: boolean
}
