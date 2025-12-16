import { NavLink } from 'react-router-dom'
import { getChainProviders } from '../config/chainProviders'
import { getProviderDisplayName } from '../config/providerNames'

interface Chain {
  id: string
  name: string
  icon: string
  path: string
  key: string
}

const chains: Chain[] = [
  { id: 'BTC', name: 'Bitcoin', icon: '/chains/btc.svg', path: '/btc', key: 'btc' },
  { id: 'COSMOS', name: 'Cosmos', icon: '/chains/atom.svg', path: '/cosmos', key: 'cosmos' },
  { id: 'ETH', name: 'Ethereum', icon: '/chains/eth.svg', path: '/eth', key: 'eth' },
  { id: 'TRON', name: 'Tron', icon: '/chains/tron.svg', path: '/tron', key: 'tron' },
  { id: 'ZEC', name: 'Zcash', icon: '/chains/zec.svg', path: '/zcash', key: 'zcash' },
  { id: 'DOGE', name: 'Dogecoin', icon: '/chains/doge.svg', path: '/doge', key: 'doge' },
  { id: 'BCH', name: 'Bitcoin Cash', icon: '/chains/bch.svg', path: '/bch', key: 'bch' },
  { id: 'LTC', name: 'Litecoin', icon: '/chains/ltc.svg', path: '/ltc', key: 'ltc' },
  { id: 'RUNE', name: 'Thorchain', icon: '/chains/rune.svg', path: '/rune', key: 'rune' },
  { id: 'MAYA', name: 'Mayachain', icon: '/chains/maya.svg', path: '/maya', key: 'maya' },
  { id: 'XRP', name: 'Ripple', icon: '/chains/xrp.svg', path: '/xrp', key: 'xrp' },
  { id: 'SOL', name: 'Solana', icon: '/chains/solana.svg', path: '/sol', key: 'sol' },
  { id: 'DOT', name: 'Polkadot', icon: '/chains/dot.svg', path: '/dot', key: 'dot' },
  { id: 'DASH', name: 'Dash', icon: '/chains/dash.svg', path: '/dash', key: 'dash' },
]

function ChainMenu() {
  return (
    <div className="flex flex-col gap-2">
      {chains.map((chain) => {
        const providers = getChainProviders(chain.key)

        return (
          <div key={chain.id} className="flex flex-col gap-1">
            <div className="px-4 py-2 text-xs font-semibold text-gray-500 uppercase tracking-wider">
              {chain.name}
            </div>
            {providers.map((provider) => (
              <NavLink
                key={provider}
                to={`${chain.path}/${provider}`}
                className={({ isActive }) =>
                  `px-4 py-2 ml-4 rounded-lg text-sm font-medium transition-all flex items-center ${
                    isActive
                      ? 'bg-blue-600 text-white shadow-md'
                      : 'text-gray-700 hover:bg-gray-100'
                  }`
                }
              >
                <img 
                  src={chain.icon} 
                  alt={chain.name}
                  className="w-4 h-4 mr-2"
                />
                {getProviderDisplayName(provider)}
              </NavLink>
            ))}
          </div>
        )
      })}
    </div>
  )
}

export default ChainMenu

