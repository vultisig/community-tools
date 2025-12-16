// @ts-ignore - protobufjs compiled file (ES module)
import types from './proto/MsgCompiled.js'

/**
 * Creates registry types for THORChain messages
 */
export function getThorchainRegistryTypes(): any[] {
  return [
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    ['/types.MsgSend', { ...(types.types.MsgSend as any) }],
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    ['/types.MsgDeposit', { ...(types.types.MsgDeposit as any) }],
  ]
}


