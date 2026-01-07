import type { Wallet } from '@wallet-standard/base'
import type { Transaction, VersionedTransaction } from '@solana/web3.js'

/**
 * Solana wallet provider interface extending Wallet Standard
 * Uses Wallet Standard types from @wallet-standard/base
 */
export interface SolanaWalletProvider extends Partial<Wallet> {
  // Standard Solana wallet methods
  connect?: () => Promise<{ publicKey: { toString: () => string } }>
  disconnect?: () => Promise<void>
  signTransaction?: (transaction: Transaction | VersionedTransaction, skipBroadcast?: boolean) => Promise<unknown>
  signAllTransactions?: (transactions: (Transaction | VersionedTransaction)[]) => Promise<unknown[]>
  signAndSendTransaction?: (transaction: Transaction | VersionedTransaction) => Promise<unknown>
  signMessage?: (message: Uint8Array, display?: string) => Promise<{ signature: Uint8Array }>
  signIn?: (params: { domain: string; statement?: string }) => Promise<unknown>
  request?: (params: { method: string; params?: unknown[] }) => Promise<unknown>
  
  // Readonly properties (from Wallet Standard)
  readonly publicKey?: { toString: () => string } | string | null
  readonly isConnected?: boolean | (() => Promise<boolean>)
  // features is already defined in Wallet interface from @wallet-standard/base
}

