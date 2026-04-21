import { ConnectMethod } from './ConnectMethod'
import { DisconnectMethod } from './DisconnectMethod'
import { RestoreConnectionMethod } from './RestoreConnectionMethod'
import { SendTransactionMethod } from './SendTransactionMethod'
import { SignDataMethod } from './SignDataMethod'
import type { ReactElement } from 'react'

interface MethodComponentProps {
  provider: unknown
  onResult: (result: unknown) => void
  onError: (error: string) => void
  onAccountUpdate?: (accounts: string[]) => void
}

type MethodComponent = (props: MethodComponentProps) => ReactElement

export const tonMethodMapping: Record<string, MethodComponent> = {
  connect: ConnectMethod,
  restoreConnection: RestoreConnectionMethod,
  disconnect: DisconnectMethod,
  sendTransaction: SendTransactionMethod,
  signData: SignDataMethod,
}

export function getMethodComponent(methodName: string): MethodComponent | null {
  return tonMethodMapping[methodName] || null
}
