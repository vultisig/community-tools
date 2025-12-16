import type { ReactElement } from 'react'

interface MethodComponentProps {
  provider: unknown
  onResult: (result: unknown) => void
  onError: (error: string) => void
  onAccountUpdate?: (accounts: string[]) => void
}

type MethodComponent = (props: MethodComponentProps) => ReactElement

export const solanaMethodMapping: Record<string, MethodComponent> = {}

export function getMethodComponent(methodName: string): MethodComponent | null {
  return solanaMethodMapping[methodName] || null
}

