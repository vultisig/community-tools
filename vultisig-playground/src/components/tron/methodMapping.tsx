import { RequestMethod } from './RequestMethod'
import { TronWebMethod } from './TronWebMethod'
import type { ReactElement } from 'react'

interface MethodComponentProps {
  provider: unknown
  onResult: (result: unknown) => void
  onError: (error: string) => void
  onAccountUpdate?: (accounts: string[]) => void
}

type MethodComponent = (props: MethodComponentProps) => ReactElement

export const tronMethodMapping: Record<string, MethodComponent> = {
  request: RequestMethod,
  tronWeb: TronWebMethod,
}

export function getMethodComponent(methodName: string): MethodComponent | null {
  return tronMethodMapping[methodName] || null
}

