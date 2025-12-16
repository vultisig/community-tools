import type { ReactElement } from 'react'
import { SignAminoMethod } from './SignAminoMethod'
import { SignDirectMethod } from './SignDirectMethod'
import { EnableMethod } from './EnableMethod'

interface MethodComponentProps {
  provider: unknown
  onResult: (result: unknown) => void
  onError: (error: string) => void
  onAccountUpdate?: (accounts: string[]) => void
}

type MethodComponent = (props: MethodComponentProps) => ReactElement

export const cosmosMethodMapping: Record<string, MethodComponent> = {
  enable: EnableMethod,
  signAmino: SignAminoMethod,
  signDirect: SignDirectMethod,
}

export function getMethodComponent(methodName: string): MethodComponent | null {
  return cosmosMethodMapping[methodName] || null
}

