import { ConnectMethod } from './ConnectMethod'
import { SignTransactionMethod } from './SignTransactionMethod'
import { SignMessageMethod } from './SignMessageMethod'
import { AccountsMethod } from './AccountsMethod'
import { DisconnectMethod } from './DisconnectMethod'
import { IsConnectedMethod } from './IsConnectedMethod'
import { PublicKeyMethod } from './PublicKeyMethod'
import { RequestMethod } from './RequestMethod'
import { SignAndSendTransactionMethod } from './SignAndSendTransactionMethod'
import { FeaturesMethod } from './FeaturesMethod'
import type { ReactElement } from 'react'

interface MethodComponentProps {
  provider: unknown
  onResult: (result: unknown) => void
  onError: (error: string) => void
  onAccountUpdate?: (accounts: string[]) => void
}

type MethodComponent = (props: MethodComponentProps) => ReactElement

export const solanaMethodMapping: Record<string, MethodComponent> = {
  connect: ConnectMethod,
  signTransaction: SignTransactionMethod,
  signMessage: SignMessageMethod,
  accounts: AccountsMethod,
  disconnect: DisconnectMethod,
  isConnected: IsConnectedMethod,
  publicKey: PublicKeyMethod,
  request: RequestMethod,
  signAndSendTransaction: SignAndSendTransactionMethod,
  features: FeaturesMethod,
  // Not implemented - these are event handlers, not direct methods:
  // handleNotification: Not a direct callable method
  // on: Event listener registration
  // off: Event listener removal
}

export function getMethodComponent(methodName: string): MethodComponent | null {
  return solanaMethodMapping[methodName] || null
}

