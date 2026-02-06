import type { ReactElement } from 'react'
import { RequestMethod } from './RequestMethod'

interface MethodComponentProps {
  provider: unknown
  onResult: (result: unknown) => void
  onError: (error: string) => void
  onAccountUpdate?: (accounts: string[]) => void
}

type MethodComponent = (props: MethodComponentProps) => ReactElement

// All THORChain actions (get_accounts, request_accounts, send_transaction, deposit_transaction) go through a single "request" tab with dropdown.
export const thorchainMethodMapping: Record<string, MethodComponent> = {
  request: RequestMethod,
}

export function getMethodComponent(methodName: string): MethodComponent | null {
  return thorchainMethodMapping[methodName] || null
}

