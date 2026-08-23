// Raw XRPL transaction builders — plain JSON objects, no signing, no network.
// Account is filled by the caller from the connected address.
// XrplTransaction covers the wallet sanitizer allowlist (Payment, OfferCreate, OfferCancel,
// TrustSet); the builders below cover the subset the panel exercises (no OfferCancel builder).

const DROPS_PER_XRP = 1_000_000n
const XRP_DECIMALS = 6
const XRP_AMOUNT_PATTERN = /^\d+(\.\d+)?$/

export interface IssuedAmount {
  currency: string
  issuer: string
  value: string
}

export type XrplAmount = string | IssuedAmount

export interface XrplPathStep {
  account?: string
  currency?: string
  issuer?: string
}

export type XrplPathSet = XrplPathStep[][]

export interface XrplPayment {
  TransactionType: 'Payment'
  Account: string
  Destination: string
  Amount: XrplAmount
  DestinationTag?: number
  SendMax?: XrplAmount
  DeliverMin?: XrplAmount
  Flags?: number
  Paths?: XrplPathSet
}

export interface XrplOfferCreate {
  TransactionType: 'OfferCreate'
  Account: string
  TakerGets: XrplAmount
  TakerPays: XrplAmount
}

export interface XrplOfferCancel {
  TransactionType: 'OfferCancel'
  Account: string
  OfferSequence: number
}

export interface XrplTrustSet {
  TransactionType: 'TrustSet'
  Account: string
  LimitAmount: IssuedAmount
}

export type XrplTransaction = XrplPayment | XrplOfferCreate | XrplOfferCancel | XrplTrustSet

export function xrpToDrops(xrp: string): string {
  const trimmed = xrp.trim()
  if (!XRP_AMOUNT_PATTERN.test(trimmed)) {
    throw new Error(`Invalid XRP amount: ${xrp}`)
  }
  const [whole, frac = ''] = trimmed.split('.')
  if (frac.length > XRP_DECIMALS) {
    throw new Error(`XRP amount supports up to ${XRP_DECIMALS} decimal places`)
  }
  const fracPadded = frac.padEnd(XRP_DECIMALS, '0')
  const drops = BigInt(whole || '0') * DROPS_PER_XRP + BigInt(fracPadded || '0')
  return drops.toString()
}

export interface PaymentParams {
  account: string
  destination: string
  xrp: string
  destinationTag?: number
}

export function buildPayment({ account, destination, xrp, destinationTag }: PaymentParams): XrplPayment {
  const tx: XrplPayment = {
    TransactionType: 'Payment',
    Account: account,
    Destination: destination,
    Amount: xrpToDrops(xrp),
  }
  if (destinationTag !== undefined) tx.DestinationTag = destinationTag
  return tx
}

export interface SelfSwapParams {
  account: string
  deliverXrp: string
  sendMax: XrplAmount
  paths?: XrplPathSet
}

export function buildSelfSwapPayment({ account, deliverXrp, sendMax, paths }: SelfSwapParams): XrplPayment {
  // Paths is optional on cross-currency payments (the engine always considers the
  // default path); only an explicitly-provided empty set is invalid (temRIPPLE_EMPTY).
  if (paths !== undefined && (paths.length === 0 || paths.every((path) => path.length === 0))) {
    throw new Error('An explicit Paths set must contain at least one non-empty path; omit paths to use default path finding')
  }

  const tx: XrplPayment = {
    TransactionType: 'Payment',
    Account: account,
    Destination: account,
    Amount: xrpToDrops(deliverXrp),
    SendMax: sendMax,
  }
  if (paths !== undefined) tx.Paths = paths
  return tx
}

export interface OfferCreateParams {
  account: string
  takerGets: XrplAmount
  takerPays: XrplAmount
}

export function buildOfferCreate({ account, takerGets, takerPays }: OfferCreateParams): XrplOfferCreate {
  return {
    TransactionType: 'OfferCreate',
    Account: account,
    TakerGets: takerGets,
    TakerPays: takerPays,
  }
}

export interface TrustSetParams {
  account: string
  currency: string
  issuer: string
  value: string
}

export function buildTrustSet({ account, currency, issuer, value }: TrustSetParams): XrplTrustSet {
  return {
    TransactionType: 'TrustSet',
    Account: account,
    LimitAmount: { currency, issuer, value },
  }
}
