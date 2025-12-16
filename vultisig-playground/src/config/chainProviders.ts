export const chainProviders: Record<string, string[]> = {
  btc: ['bitcoin'],
  cosmos: ['cosmos', 'keplr'],
  eth: ['ethereum'],
  tron: ['tron'],
  zcash: ['zcash'],
  doge: ['dogecoin'],
  bch: ['bitcoincash'],
  ltc: ['litecoin'],
  rune: ['thorchain'],
  maya: ['mayachain'],
  xrp: ['ripple'],
  sol: ['solana'],
  dot: ['polkadot'],
  dash: ['dash'],
}

export function getChainProviders(chainName: string): string[] {
  return chainProviders[chainName] || []
}
