import type { ReactElement } from 'react'
import { RequestMethod } from './RequestMethod'
import { GenericMethod } from './GenericMethod'

interface MethodComponentProps {
  provider: unknown
  onResult: (result: unknown) => void
  onError: (error: string) => void
  onAccountUpdate?: (accounts: string[]) => void
}

type MethodComponent = (props: MethodComponentProps) => ReactElement

export const polkadotMethodMapping: Record<string, MethodComponent> = {
  request: RequestMethod,
}

export function getMethodComponent(methodName: string): MethodComponent | null {
  if (polkadotMethodMapping[methodName]) {
    return polkadotMethodMapping[methodName]
  }

  return (props: MethodComponentProps) => (
    <GenericMethod
      provider={props.provider}
      methodName={methodName}
      onResult={props.onResult}
      onError={props.onError}
      onAccountUpdate={props.onAccountUpdate}
    />
  )
}

