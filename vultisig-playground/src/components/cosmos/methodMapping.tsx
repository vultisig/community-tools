import type { ReactElement } from 'react'
import { SignAminoMethod } from './SignAminoMethod'
import { SignDirectMethod } from './SignDirectMethod'
import { EnableMethod } from './EnableMethod'
import { RequestMethod } from './RequestMethod'

interface MethodComponentProps {
  provider: unknown
  onResult: (result: unknown) => void
  onError: (error: string) => void
  onAccountUpdate?: (accounts: string[]) => void
}

type MethodComponent = (props: MethodComponentProps) => ReactElement

// Provider-aware mappings:
// - Native (`window.vultisig.cosmos`) exposes `request(...)`
// - Keplr (`window.vultisig.keplr`) exposes Keplr-style methods (enable/signAmino/signDirect)
export const cosmosNativeMethodMapping: Record<string, MethodComponent> = {
  request: RequestMethod,
}

export const cosmosKeplrMethodMapping: Record<string, MethodComponent> = {
  enable: EnableMethod,
  signAmino: SignAminoMethod,
  signDirect: SignDirectMethod,
}

export function getMethodComponent(providerName: string, methodName: string): MethodComponent | null {
  if (providerName === 'cosmos') {
    return cosmosNativeMethodMapping[methodName] || null
  }
  if (providerName === 'keplr') {
    return cosmosKeplrMethodMapping[methodName] || null
  }
  return null
}

