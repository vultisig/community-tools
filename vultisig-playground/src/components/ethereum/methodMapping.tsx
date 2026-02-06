import type { ReactElement } from 'react'
import { RequestMethod } from './RequestMethod'

interface MethodComponentProps {
  provider: unknown
  onResult: (result: unknown) => void
  onError: (error: string) => void
  onAccountUpdate?: (accounts: string[]) => void
}

type MethodComponent = (props: MethodComponentProps) => ReactElement

// All Ethereum actions (eth_sendTransaction, eth_signTypedData_v4, etc.) go through a single "request" tab with dropdown.
export const ethereumMethodMapping: Record<string, MethodComponent> = {
  request: RequestMethod,
}

export function getMethodComponent(methodName: string): MethodComponent | null {
  return ethereumMethodMapping[methodName] || null
}

