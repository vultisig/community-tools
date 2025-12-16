import type { ReactElement } from 'react'

interface MethodComponentProps {
  provider: unknown
  onResult: (result: unknown) => void
  onError: (error: string) => void
  onAccountUpdate?: (accounts: string[]) => void
}

type MethodComponent = (props: MethodComponentProps) => ReactElement

export const litecoinMethodMapping: Record<string, MethodComponent> = {}

export function getMethodComponent(methodName: string): MethodComponent | null {
  return litecoinMethodMapping[methodName] || null
}

