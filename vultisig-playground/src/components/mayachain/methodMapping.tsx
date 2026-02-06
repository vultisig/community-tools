import type { ReactElement } from 'react'
import { RequestMethod } from './RequestMethod'

interface MethodComponentProps {
  provider: unknown
  onResult: (result: unknown) => void
  onError: (error: string) => void
  onAccountUpdate?: (accounts: string[]) => void
}

type MethodComponent = (props: MethodComponentProps) => ReactElement

// All MayaChain actions (send_transaction, deposit_transaction) go through a single "request" tab with dropdown.
export const mayachainMethodMapping: Record<string, MethodComponent> = {
  request: RequestMethod,
}

export function getMethodComponent(methodName: string): MethodComponent | null {
  return mayachainMethodMapping[methodName] || null
}

