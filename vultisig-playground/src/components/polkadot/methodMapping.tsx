import InjectedWeb3Playground from './InjectedWeb3Playground'
import type { ReactElement } from 'react'

interface MethodComponentProps {
  provider: unknown
  onResult: (result: unknown) => void
  onError: (error: string) => void
  onAccountUpdate?: (accounts: string[]) => void
}

type MethodComponent = (props: MethodComponentProps) => ReactElement

export const polkadotMethodMapping: Record<string, MethodComponent> = {
  injectedWeb3: ({ onResult, onError }) => (
    <InjectedWeb3Playground onResult={onResult} onError={onError} />
  ),
}

export function getMethodComponent(methodName: string): MethodComponent | null {
  return polkadotMethodMapping[methodName] || null
}
