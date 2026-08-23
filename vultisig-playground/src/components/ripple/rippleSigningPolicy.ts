export type RippleSignMode = 'sign' | 'submit'

export const PRESET_BROADCAST_ERROR =
  'Bundled examples are sign-only. Edit the JSON before broadcasting.'

interface RippleSigningMethods {
  signTransaction: (params: { transaction: Record<string, unknown> }) => Promise<unknown>
  submitTransaction: (params: { transaction: Record<string, unknown> }) => Promise<unknown>
}

export function isPresetBroadcastBlocked(
  mode: RippleSignMode,
  isPresetSelected: boolean,
): boolean {
  return mode === 'submit' && isPresetSelected
}

interface ExecuteRippleTransactionParams {
  mode: RippleSignMode
  isPresetSelected: boolean
  transaction: Record<string, unknown>
  provider: RippleSigningMethods
}

export async function executeRippleTransaction({
  mode,
  isPresetSelected,
  transaction,
  provider,
}: ExecuteRippleTransactionParams): Promise<unknown> {
  if (isPresetBroadcastBlocked(mode, isPresetSelected)) {
    throw new Error(PRESET_BROADCAST_ERROR)
  }

  return mode === 'submit'
    ? provider.submitTransaction({ transaction })
    : provider.signTransaction({ transaction })
}
