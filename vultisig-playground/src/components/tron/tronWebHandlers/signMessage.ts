import type { TronWeb } from 'tronweb'
import type { TronWebExecuteContext } from './types'

/**
 * Prepara mensaje para TRON legacy signMessage (V1), según documentación oficial.
 * Flujo: text → hex (sin 0x) → byteArray → sha3 (keccak256) → hex sin 0x.
 */
export function prepareTronV1FromUtf8Text(text: string, tronWeb: TronWeb): string {
  const trimmed = text.trim()
  const hexStrWithout0x = tronWeb.toHex(trimmed).replace(/^0x/, '')
  const byteArray = tronWeb.utils.code.hexStr2byteArray(hexStrWithout0x)
  // Documentación oficial usa sha3(byteArray); tipos de TronWeb solo declaran string
  const strHash = (tronWeb.sha3 as (input: string | number[]) => string)(byteArray).replace(/^0x/, '')
  return strHash.toLowerCase()
}

/** Resultado de un flujo sign + verify con un valor de useTronHeader */
export interface SignMessageVariantResult {
  signature: string
  verified: boolean
  verificationError: string | null
}

export interface SignMessageResult {
  hexMsg: string
  expectedAddress: string | null
  /** Ejemplo con useTronHeader = true (por defecto en signMessage). Null si solo se ejecutó withoutTronHeader. */
  withTronHeader: SignMessageVariantResult | null
  /** Ejemplo con useTronHeader = false (tercer param de signMessage). Null si solo se ejecutó withTronHeader. */
  withoutTronHeader: SignMessageVariantResult | null
}

export async function executeSignMessage(ctx: TronWebExecuteContext): Promise<SignMessageResult> {
  const { tronWeb, messageToSign, signMessageUseTronHeader } = ctx
  const message = (messageToSign ?? '').trim()

  if (!message) {
    throw new Error('Message to sign is required')
  }

  if (!tronWeb) {
    throw new Error('tronWeb is not available')
  }

  const { trx } = tronWeb
  if (!trx?.signMessage || typeof trx.signMessage !== 'function') {
    throw new Error('tronWeb.trx.sign (legacy signMessage) is not available')
  }
  if (!trx.verifyMessage || typeof trx.verifyMessage !== 'function') {
    throw new Error('tronWeb.trx.verifyMessage is not available')
  }

  console.log('message', message)
  const hexMsg = prepareTronV1FromUtf8Text(message, tronWeb)
  console.log('hexMsg', hexMsg)
  const rawAddress = tronWeb.defaultAddress?.base58
  const expectedAddress = typeof rawAddress === 'string' ? rawAddress : null

  function adjustRecoveryTail(s: string): string {
    const tail = s.substring(128, 130)
    if (tail === '01') return s.substring(0, 128) + '1c'
    if (tail === '00') return s.substring(0, 128) + '1b'
    return s
  }

  async function signAndVerify(useTronHeader: boolean): Promise<SignMessageVariantResult> {
    const raw = await trx.signMessage(hexMsg, undefined, useTronHeader)
    let signedStr = typeof raw === 'string' ? raw.replace(/^0x/, '') : ''
    signedStr = adjustRecoveryTail(signedStr)
    let verified = false
    let verificationError: string | null = null
    if (!expectedAddress) {
      verificationError =
        'Cannot verify signature: no address is set. You must run the request method (e.g. requestAccounts) first to connect the account and get tronWeb.defaultAddress.'
    } else {
      try {
        verified = await trx.verifyMessage(hexMsg, signedStr, expectedAddress, useTronHeader)
        if (!verified) verificationError = 'Signature does not match expected address'
      } catch (err) {
        verificationError = (err as Error).message || 'Verification failed'
      }
    }
    return { signature: signedStr, verified, verificationError }
  }

  const useTronHeader = signMessageUseTronHeader ?? false
  const withTronHeader = useTronHeader ? await signAndVerify(true) : null
  const withoutTronHeader = !useTronHeader ? await signAndVerify(false) : null

  return {
    hexMsg,
    expectedAddress,
    withTronHeader,
    withoutTronHeader,
  }
}
