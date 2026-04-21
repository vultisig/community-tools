import type { ReactElement } from 'react'
import type { MethodComponentProps } from './types'
import { IsEnabledMethod } from './IsEnabledMethod'
import { EnableMethod } from './EnableMethod'
import { GetNetworkIdMethod } from './GetNetworkIdMethod'
import { GetExtensionsMethod } from './GetExtensionsMethod'
import { GetUsedAddressesMethod } from './GetUsedAddressesMethod'
import { GetUnusedAddressesMethod } from './GetUnusedAddressesMethod'
import { GetChangeAddressMethod } from './GetChangeAddressMethod'
import { GetRewardAddressesMethod } from './GetRewardAddressesMethod'
import { GetBalanceMethod } from './GetBalanceMethod'
import { GetUtxosMethod } from './GetUtxosMethod'
import { SignDataMethod } from './SignDataMethod'
import { SignTxMethod } from './SignTxMethod'
import { SubmitTxMethod } from './SubmitTxMethod'

type MethodComponent = (props: MethodComponentProps) => ReactElement

export const cardanoMethodMapping: Record<string, MethodComponent> = {
  isEnabled: IsEnabledMethod,
  enable: EnableMethod,
  getNetworkId: GetNetworkIdMethod,
  getExtensions: GetExtensionsMethod,
  getUsedAddresses: GetUsedAddressesMethod,
  getUnusedAddresses: GetUnusedAddressesMethod,
  getChangeAddress: GetChangeAddressMethod,
  getRewardAddresses: GetRewardAddressesMethod,
  getBalance: GetBalanceMethod,
  getUtxos: GetUtxosMethod,
  signData: SignDataMethod,
  signTx: SignTxMethod,
  submitTx: SubmitTxMethod,
}

export function getMethodComponent(methodName: string): MethodComponent | null {
  return cardanoMethodMapping[methodName] || null
}
