import { StargateClient } from '@cosmjs/stargate'

export interface CosmosAccountInfo {
  address: string
  accountNumber: string
  sequence: string
}

export const getRpcUrl = (chainId: string): string => {
  const rpcMap: Record<string, string> = {
    'cosmoshub-4': 'https://cosmos-rpc.polkachu.com',
    'thorchain-1': 'https://rpc.ninerealms.com',
  }
  return rpcMap[chainId] || `https://rpc.cosmos.directory/${chainId}`
}

export const fetchCosmosAccountInfo = async (
  provider: unknown,
  chainId: string
): Promise<CosmosAccountInfo> => {
  if (!chainId.trim()) {
    throw new Error('Chain ID is required')
  }

  const providerObj = provider as unknown as Record<string, unknown>

  // Enable connection using Keplr's enable method
  if (!providerObj.enable || typeof providerObj.enable !== 'function') {
    throw new Error('enable method is not available')
  }
  await (providerObj.enable as (chainId: string) => Promise<void>)(chainId)

  // Get address using getKey
  if (!providerObj.getKey || typeof providerObj.getKey !== 'function') {
    throw new Error('getKey method is not available')
  }
  const key = await (providerObj.getKey as (chainId: string) => Promise<{
    bech32Address: string
  }>)(chainId)

  if (!key?.bech32Address) {
    throw new Error('Failed to get address from getKey')
  }
  const signerAddress = key.bech32Address

  // Get accountNumber and sequence using StargateClient
  const rpcUrl = getRpcUrl(chainId)
  const client = await StargateClient.connect(rpcUrl)
  const account = await client.getAccount(signerAddress)
  client.disconnect()

  let accountNumber = '0'
  let sequence = '0'

  if (account) {
    if (account.accountNumber !== undefined && account.accountNumber !== null) {
      accountNumber = typeof account.accountNumber === 'string' 
        ? account.accountNumber 
        : String(account.accountNumber)
    }

    if (account.sequence !== undefined && account.sequence !== null) {
      sequence = typeof account.sequence === 'string' 
        ? account.sequence 
        : String(account.sequence)
    }
  }

  return {
    address: signerAddress,
    accountNumber,
    sequence,
  }
}

export const enableCosmosChain = async (
  provider: unknown,
  chainId: string
): Promise<void> => {
  if (!chainId.trim()) {
    throw new Error('Chain ID is required')
  }

  const providerObj = provider as unknown as Record<string, unknown>

  if (!providerObj.enable || typeof providerObj.enable !== 'function') {
    throw new Error('enable method is not available')
  }

  await (providerObj.enable as (chainId: string) => Promise<void>)(chainId)
}

