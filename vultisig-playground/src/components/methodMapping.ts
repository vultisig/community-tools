import { getMethodComponent as getBitcoinMethodComponent } from './bitcoin/methodMapping'
import { getMethodComponent as getCosmosMethodComponent } from './cosmos/methodMapping'
import { getMethodComponent as getEthereumMethodComponent } from './ethereum/methodMapping'
import { getMethodComponent as getTronMethodComponent } from './tron/methodMapping'
import { getMethodComponent as getZcashMethodComponent } from './zcash/methodMapping'
import { getMethodComponent as getDogecoinMethodComponent } from './dogecoin/methodMapping'
import { getMethodComponent as getBchMethodComponent } from './bch/methodMapping'
import { getMethodComponent as getLitecoinMethodComponent } from './litecoin/methodMapping'
import { getMethodComponent as getThorchainMethodComponent } from './thorchain/methodMapping'
import { getMethodComponent as getMayachainMethodComponent } from './mayachain/methodMapping'
import { getMethodComponent as getRippleMethodComponent } from './ripple/methodMapping'
import { getMethodComponent as getSolanaMethodComponent } from './solana/methodMapping'
import { getMethodComponent as getPolkadotMethodComponent } from './polkadot/methodMapping'
import { getMethodComponent as getDashMethodComponent } from './dash/methodMapping'
import type { ReactElement } from 'react'

interface MethodComponentProps {
  provider: unknown
  onResult: (result: unknown) => void
  onError: (error: string) => void
  onAccountUpdate?: (accounts: string[]) => void
}

type MethodComponent = (props: MethodComponentProps) => ReactElement

export function getMethodComponent(chainName: string, methodName: string): MethodComponent | null {
  switch (chainName.toLowerCase()) {
    case 'bitcoin':
    case 'btc':
      return getBitcoinMethodComponent(methodName)
    case 'cosmos':
      return getCosmosMethodComponent(methodName)
    case 'ethereum':
    case 'eth':
      return getEthereumMethodComponent(methodName)
    case 'tron':
      return getTronMethodComponent(methodName)
    case 'zcash':
      return getZcashMethodComponent(methodName)
    case 'dogecoin':
    case 'doge':
      return getDogecoinMethodComponent(methodName)
    case 'bch':
      return getBchMethodComponent(methodName)
    case 'litecoin':
    case 'ltc':
      return getLitecoinMethodComponent(methodName)
    case 'thorchain':
    case 'rune':
      return getThorchainMethodComponent(methodName)
    case 'mayachain':
    case 'maya':
      return getMayachainMethodComponent(methodName)
    case 'ripple':
    case 'xrp':
      return getRippleMethodComponent(methodName)
    case 'solana':
    case 'sol':
      return getSolanaMethodComponent(methodName)
    case 'polkadot':
    case 'dot':
      return getPolkadotMethodComponent(methodName)
    case 'dash':
      return getDashMethodComponent(methodName)
    default:
      return null
  }
}

