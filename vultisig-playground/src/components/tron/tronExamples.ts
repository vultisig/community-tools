// @ts-ignore - tronweb types may not be available
import type TronWeb from 'tronweb'

export interface TronTransaction {
  raw_data: {
    contract: Array<{
      type: string
      parameter: {
        type_url: string
        value: unknown
      }
    }>
    ref_block_bytes: string
    ref_block_hash: string
    expiration: number
    timestamp: number
    fee_limit?: number
    data?: string
  }
  raw_data_hex?: string
}


function getTronWeb(): TronWeb | null {
  if (!window.vultisig?.tron?.tronWeb) {
    return null
  }
  return window.vultisig.tron.tronWeb as TronWeb
}

async function buildTransferTRX(
  fromAddress: string,
  toAddress: string,
  tronWeb: TronWeb
): Promise<TronTransaction> {
  try {
    if (!tronWeb.transactionBuilder?.sendTrx) {
      throw new Error('sendTrx method not available')
    }
    console.log('toAddress', toAddress)
    console.log('fromAddress', fromAddress)
    return await tronWeb.transactionBuilder.sendTrx(toAddress, 50000, fromAddress)
  } catch (error) {
    console.log('error', error)
    throw new Error(`Failed to build TRX transfer: ${(error as Error).message}`)
  }
}

async function buildTransferUSDT(
  fromAddress: string,
  toAddress: string,
  tronWeb: TronWeb
): Promise<TronTransaction> {
  try {
    if (!tronWeb.transactionBuilder?.triggerSmartContract) {
      throw new Error('triggerSmartContract method not available')
    }

    const USDT_CONTRACT = 'TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t'

    const tronWebFull = window.vultisig?.tron?.tronWeb as { address?: { toHex?: (address: string) => string } } | undefined

    if (!tronWebFull?.address?.toHex) {
      throw new Error('address.toHex method not available')
    }

    const contractHex = tronWebFull.address.toHex(USDT_CONTRACT)
    const fromHex = tronWebFull.address.toHex(fromAddress)
    const toHex = tronWebFull.address.toHex(toAddress)

    const options = { feeLimit: 15_000_000, callValue: 0 }

    const params = [
      { type: 'address', value: toHex },
      { type: 'uint256', value: '50000' },
    ]

    const result =  await tronWeb.transactionBuilder.triggerSmartContract(
      contractHex,
      'transfer(address,uint256)',
      options,
      params,
      fromHex
    )
    return result.transaction
  } catch (error) {
    console.error('Error building USDT transfer:', error)
    throw new Error(`Failed to build USDT transfer: ${(error as Error).message}`)
  }
}

export const getTronTransactionExamples = async (
  fromAddress: string,
  toAddress?: string,
  exampleType?: string
): Promise<Record<string, TronTransaction> | TronTransaction> => {
  const defaultToAddress = toAddress || fromAddress
  const tronWeb = getTronWeb()
  
  if (!tronWeb?.transactionBuilder) {
    throw new Error('TronWeb transactionBuilder not available. Please use the "request" method first to connect your Tron account.')
  }
  
  const transactionBuilder = tronWeb.transactionBuilder
  
  if (exampleType) {
    switch (exampleType) {
      case 'transferTRX':
        if (!transactionBuilder.sendTrx) {
          throw new Error('transactionBuilder.sendTrx method not available')
        }
        return await buildTransferTRX(fromAddress, defaultToAddress, tronWeb)
      
      case 'triggerSmartContractGeneric':
        if (!transactionBuilder.triggerSmartContract) {
          throw new Error('transactionBuilder.triggerSmartContract method not available')
        }
        return await buildTransferUSDT(fromAddress, defaultToAddress, tronWeb)
      
      default:
        throw new Error(`Unknown example type: ${exampleType}`)
    }
  }
  
  return {}
}

export const getTronExampleDescriptions = (): Record<string, string> => ({
  transferTRX: 'TRX Transfer - Transfer 0.05 TRX',
  triggerSmartContractGeneric: 'USDT TRC20 Transfer - Transfer 0.05 USDT (TriggerSmartContract)',
})

