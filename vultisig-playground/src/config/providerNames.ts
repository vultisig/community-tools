export const providerDisplayNames: Record<string, string> = {
  cosmos: 'Native',
  keplr: 'Keplr',
  bitcoin: 'Native',
  ethereum: 'Native',
  tron: 'Native',
  zcash: 'Native',
  dogecoin: 'Native',
  bch: 'Native',
  litecoin: 'Native',
  thorchain: 'Native',
  mayachain: 'Native',
  ripple: 'Native',
  solana: 'Native',
  polkadot: 'Native',
  dash: 'Native',
}

export function getProviderDisplayName(providerName: string): string {
  return providerDisplayNames[providerName] || providerName.charAt(0).toUpperCase() + providerName.slice(1)
}

