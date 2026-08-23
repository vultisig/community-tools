export interface RippleProvider {
  getAddress: () => Promise<{ address: string }>
  getPublicKey: () => Promise<{ address: string; publicKey: string }>
  signTransaction: (params: { transaction: Record<string, unknown> }) => Promise<{ signature: string }>
  submitTransaction: (params: { transaction: Record<string, unknown> }) => Promise<{ hash: string }>
}
