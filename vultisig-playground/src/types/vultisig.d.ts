export interface VultisigProvider {
  request(params: { method: string; params?: unknown[] }): Promise<unknown>
  on(event: string, handler: (data?: unknown) => void): void
  removeListener(event: string, handler: (data?: unknown) => void): void
}

export interface VultisigBitcoinProvider extends VultisigProvider {
  signPSBT?: (
    psbt: Buffer | Uint8Array,
    options: { inputsToSign: Array<{ address: string; signingIndexes: number[]; sigHash: number }> },
    finalize?: boolean
  ) => Promise<Buffer>
}

export interface VultisigVault {
  name?: string
  [key: string]: unknown
}

interface VultisigWindow {
  vultisig?: {
    bitcoin?: VultisigBitcoinProvider
    cosmos?: VultisigProvider
    keplr?: VultisigProvider
    ethereum?: VultisigProvider
    tron?: VultisigTronProvider
    zcash?: VultisigProvider
    dogecoin?: VultisigProvider
    bch?: VultisigProvider
    litecoin?: VultisigProvider
    thorchain?: VultisigProvider
    mayachain?: VultisigProvider
    ripple?: VultisigProvider
    solana?: VultisigProvider
    dash?: VultisigProvider
    ton?: { tonconnect: unknown }
    [key: string]: unknown
  }
}

export interface PolkadotInjectedAccount {
  address: string
  genesisHash?: string
  name?: string
  type?: 'ed25519' | 'sr25519' | 'ecdsa'
}

export interface PolkadotSignerPayloadJSON {
  address: string
  blockHash: string
  blockNumber: string
  era: string
  genesisHash: string
  method: string
  nonce: string
  specVersion: string
  tip: string
  transactionVersion: string
  signedExtensions: string[]
  version: number
}

export interface PolkadotSignerPayloadRaw {
  address: string
  data: string
  type: 'bytes' | 'payload'
}

export interface PolkadotSignerResult {
  id: number
  signature: string
}

export interface PolkadotInjectedProvider {
  enable: (origin?: string) => Promise<{
    accounts: {
      get: () => Promise<PolkadotInjectedAccount[]>
      subscribe: (cb: (accounts: PolkadotInjectedAccount[]) => void) => () => void
    }
    signer: {
      signPayload: (payload: PolkadotSignerPayloadJSON) => Promise<PolkadotSignerResult>
      signRaw: (payload: PolkadotSignerPayloadRaw) => Promise<PolkadotSignerResult>
    }
  }>
}

declare global {
  interface Window extends VultisigWindow {
    injectedWeb3?: Record<string, PolkadotInjectedProvider>
  }
}

