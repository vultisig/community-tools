import type { ReactElement } from 'react'
import { SignTypedDataV4Method } from './SignTypedDataV4Method'

interface MethodComponentProps {
  provider: unknown
  onResult: (result: unknown) => void
  onError: (error: string) => void
  onAccountUpdate?: (accounts: string[]) => void
}

type MethodComponent = (props: MethodComponentProps) => ReactElement

export const ethereumMethodMapping: Record<string, MethodComponent> = {
  eth_signTypedData_v4: SignTypedDataV4Method,
}

export function getMethodComponent(methodName: string): MethodComponent | null {
  return ethereumMethodMapping[methodName] || null
}

