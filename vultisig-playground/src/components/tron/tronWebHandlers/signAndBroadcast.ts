import type { TronWebExecuteContext } from './types'

export interface SignAndBroadcastResult {
  signedTransaction: unknown
  broadcastResult: unknown
}

export async function executeSignAndBroadcast(ctx: TronWebExecuteContext): Promise<SignAndBroadcastResult> {
  const { tronWeb, transactionJson } = ctx

  if (!transactionJson?.trim()) {
    throw new Error('Transaction JSON is required')
  }

  let transaction: unknown
  try {
    transaction = JSON.parse(transactionJson)
  } catch {
    throw new Error('Invalid JSON format for transaction')
  }

  if (!tronWeb?.trx || typeof tronWeb.trx !== 'object') {
    throw new Error('trx object not available in tronWeb')
  }

  const trx = tronWeb.trx
  if (!trx.sign || typeof trx.sign !== 'function') {
    throw new Error('trx.sign method not available')
  }

  const signedTransaction = await trx.sign(transaction)

  let broadcastResult: unknown = null
  if (tronWeb.trx.sendRawTransaction && typeof tronWeb.trx.sendRawTransaction === 'function') {
    try {
      broadcastResult = await tronWeb.trx.sendRawTransaction(signedTransaction)
    } catch (e) {
      console.error('Error broadcasting transaction:', e)
      broadcastResult = 'not available'
    }
  } else {
    broadcastResult = 'not available'
  }

  return { signedTransaction, broadcastResult }
}
