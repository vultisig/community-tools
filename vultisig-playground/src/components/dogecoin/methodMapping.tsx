import { RequestMethod } from './RequestMethod'
import { RequestAccountsMethod } from './RequestAccountsMethod'
import { SignPsbtMethod } from './SignPsbtMethod'
import type { ReactElement } from 'react'

interface MethodComponentProps {
  provider: unknown
  onResult: (result: unknown) => void
  onError: (error: string) => void
  onAccountUpdate?: (accounts: string[]) => void
}

type MethodComponent = (props: MethodComponentProps) => ReactElement

export const dogecoinMethodMapping: Record<string, MethodComponent> = {
  request: RequestMethod,
  requestAccounts: RequestAccountsMethod,
  signPSBT: SignPsbtMethod,
}

export function getMethodComponent(methodName: string): MethodComponent | null {
  return dogecoinMethodMapping[methodName] || null
}

