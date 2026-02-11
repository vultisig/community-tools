import type { TronWebMethodId, TronWebExecuteContext } from './types'
import { executeDefaultAddress } from './defaultAddress'
import { executeSignMessage } from './signMessage'
import { executeSignMessageV2 } from './signMessageV2'
import { executeSignAndBroadcast } from './signAndBroadcast'

export type { TronWebMethodId, TronWebExecuteContext } from './types'
export { executeDefaultAddress } from './defaultAddress'
export type { SignMessageResult, SignMessageVariantResult } from './signMessage'
export { executeSignMessage } from './signMessage'
export type { SignMessageV2Result } from './signMessageV2'
export { executeSignMessageV2 } from './signMessageV2'
export type { SignAndBroadcastResult } from './signAndBroadcast'
export { executeSignAndBroadcast } from './signAndBroadcast'

/**
 * Runs the requested TronWeb method and returns the result.
 * Throws on validation or execution error.
 */
export async function runTronWebMethod(
  method: TronWebMethodId,
  ctx: TronWebExecuteContext
): Promise<unknown> {
  switch (method) {
    case 'defaultAddress':
      return executeDefaultAddress(ctx)
    case 'signMessage':
      return executeSignMessage(ctx)
    case 'signMessageV2':
      return executeSignMessageV2(ctx)
    case 'signAndBroadcast':
      return executeSignAndBroadcast(ctx)
    default: {
      const exhaustive: never = method
      throw new Error(`Unknown TronWeb method: ${String(exhaustive)}`)
    }
  }
}
