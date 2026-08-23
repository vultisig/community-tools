import { GetAddressMethod } from './GetAddressMethod'
import { SignTransactionMethod } from './SignTransactionMethod'
import type { ReactElement } from 'react'

interface MethodComponentProps {
  provider: unknown
  onResult: (result: unknown) => void
  onError: (error: string) => void
  onAccountUpdate?: (accounts: string[]) => void
}

type MethodComponent = (props: MethodComponentProps) => ReactElement

export const rippleMethodMapping: Record<string, MethodComponent> = {
  getAddress: GetAddressMethod,
  signTransaction: SignTransactionMethod,
}

export function getMethodComponent(methodName: string): MethodComponent | null {
  return rippleMethodMapping[methodName] || null
}
