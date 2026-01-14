import type { Wallet } from '@wallet-standard/base'
import type { Transaction, VersionedTransaction } from '@solana/web3.js'

export interface SolanaWalletProvider extends Partial<Wallet> {
  connect?: () => Promise<{ publicKey: { toString: () => string } }>
  disconnect?: () => Promise<void>
  signTransaction?: (transaction: Transaction | VersionedTransaction, skipBroadcast?: boolean) => Promise<unknown>
  signAllTransactions?: (transactions: (Transaction | VersionedTransaction)[]) => Promise<unknown[]>
  signAndSendTransaction?: (transaction: Transaction | VersionedTransaction) => Promise<unknown>
  signMessage?: (message: Uint8Array, display?: string) => Promise<{ signature: Uint8Array }>
  signIn?: (params: { domain: string; statement?: string }) => Promise<unknown>
  request?: (params: { method: string; params?: unknown[] }) => Promise<unknown>
  
  readonly publicKey?: { toString: () => string } | string | null
  readonly isConnected?: boolean | (() => Promise<boolean>)
}

