import type { TronWebExecuteContext } from './types'

export interface SignMessageV2Result {
  signature: string
  recoveredAddress: string
  expectedAddress: string | null
  verified: boolean
  /** Error message when verification failed; null when verified or when no expected address */
  verificationError: string | null
}

export async function executeSignMessageV2(ctx: TronWebExecuteContext): Promise<SignMessageV2Result> {
  const { tronWeb, messageToSign } = ctx
  const message = (messageToSign ?? '').trim()

  if (!message) {
    throw new Error('Message to sign is required')
  }

  if (!tronWeb) {
    throw new Error('tronWeb is not available')
  }

  const { trx } = tronWeb
  if (!trx?.signMessageV2 || typeof trx.signMessageV2 !== 'function') {
    throw new Error('tronWeb.trx.signMessageV2 (TIP-191) is not available')
  }
  if (!trx.verifyMessageV2 || typeof trx.verifyMessageV2 !== 'function') {
    throw new Error('tronWeb.trx.verifyMessageV2 is not available')
  }

  const signatureResult = trx.signMessageV2(message)
  const signature = await Promise.resolve(signatureResult as string | Promise<string>).then((s) => String(s))

  const recoveredAddress = await trx.verifyMessageV2(message, signature)
  const rawAddress = tronWeb.defaultAddress?.base58
  const expectedAddress = typeof rawAddress === 'string' ? rawAddress : null
  const verified = !!expectedAddress && recoveredAddress === expectedAddress
  let verificationError: string | null = null
  if (!expectedAddress) {
    verificationError =
      'Cannot verify signature: no address is set. You must run the request method (e.g. requestAccounts) first to connect the account and get tronWeb.defaultAddress.'
  } else if (!verified) {
    verificationError = 'Recovered address does not match expected address'
  }

  return {
    signature,
    recoveredAddress,
    expectedAddress,
    verified,
    verificationError,
  }
}
