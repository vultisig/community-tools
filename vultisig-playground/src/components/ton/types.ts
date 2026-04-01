export interface TonConnectDeviceInfo {
  platform: string
  appName: string
  appVersion: string
  maxProtocolVersion: number
  features: unknown[]
}

export interface TonConnectWalletInfo {
  name: string
  image: string
  about_url: string
}

export interface TonAddrItemReply {
  name: 'ton_addr'
  address: string
  network: string
  publicKey: string
  walletStateInit: string
}

export interface TonProofItemReply {
  name: 'ton_proof'
  proof: {
    timestamp: number
    domain: {
      lengthBytes: number
      value: string
    }
    payload: string
    signature: string
  }
}

export type ConnectItemReply = TonAddrItemReply | TonProofItemReply

export interface ConnectEventSuccess {
  event: 'connect'
  id: number
  payload: {
    items: ConnectItemReply[]
    device: TonConnectDeviceInfo
  }
}

export interface ConnectEventError {
  event: 'connect_error'
  id: number
  payload: {
    code: number
    message: string
  }
}

export type ConnectEvent = ConnectEventSuccess | ConnectEventError

export interface ConnectRequest {
  manifestUrl: string
  items: Array<{ name: string; payload?: string }>
}

export interface WalletEvent {
  event: string
  id: number
  payload: unknown
}

export interface TonConnectBridge {
  deviceInfo: TonConnectDeviceInfo
  walletInfo?: TonConnectWalletInfo
  protocolVersion: number
  isWalletBrowser: boolean
  connect: (protocolVersion: number, request: ConnectRequest) => Promise<ConnectEvent>
  restoreConnection: () => Promise<ConnectEvent>
  disconnect: () => Promise<void>
  send: (message: { method: string; params: string[]; id: string }) => Promise<unknown>
  listen: (callback: (event: WalletEvent) => void) => () => void
}

export interface TonProvider {
  tonconnect: TonConnectBridge
}
