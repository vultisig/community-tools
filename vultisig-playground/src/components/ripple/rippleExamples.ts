import {
  buildOfferCreate,
  buildPayment,
  buildSelfSwapPayment,
  buildTrustSet,
  xrpToDrops,
} from './rippleTransactions'

// Adversarial cases reproduce the keysign-integrity XRPL gaps documented in
// keysign-integrity chain-fields.md (issues windows#4595 / ios#5081 / android#5555):
// fields that change what actually settles but may not surface in the wallet UI.
// Every builder targets the connected account (self) — never a hardcoded third party —
// so a "Sign & submit" misclick can't drain funds to an address the dev doesn't control.

// tfPartialPayment: Amount becomes a ceiling, not a guaranteed delivery.
const TF_PARTIAL_PAYMENT = 131072

// Bitstamp USD appears only as a currency ISSUER (never a fund destination).
const BITSTAMP_USD_ISSUER = 'rvYAfWj5gh67oV6fW32ZzP3Aw4Eubs59B'

export type RippleExampleCategory = 'legit' | 'adversarial'

export interface RippleExample {
  id: string
  label: string
  description: string
  category: RippleExampleCategory
  expectedWalletBehavior?: string
  build: (account: string) => object
}

export const rippleExamples: RippleExample[] = [
  {
    id: 'nativePayment',
    label: 'Native XRP payment',
    description: 'Send 1 XRP to yourself; edit Destination to a real address to actually send elsewhere.',
    category: 'legit',
    build: (account) => buildPayment({ account, destination: account, xrp: '1' }),
  },
  {
    id: 'selfSwap',
    label: 'Self cross-currency payment',
    description: 'Cross-currency-style Payment delivering 1 XRP to yourself with a 1.5 XRP SendMax cap.',
    category: 'legit',
    build: (account) => buildSelfSwapPayment({ account, deliverXrp: '1', sendMaxXrp: '1.5' }),
  },
  {
    id: 'offerCreate',
    label: 'OfferCreate (DEX)',
    description: 'Offer to buy 10 USD (Bitstamp) paying up to 5 XRP on the XRPL DEX.',
    category: 'legit',
    build: (account) =>
      buildOfferCreate({
        account,
        takerGets: xrpToDrops('5'),
        takerPays: { currency: 'USD', issuer: BITSTAMP_USD_ISSUER, value: '10' },
      }),
  },
  {
    id: 'trustSet',
    label: 'TrustSet (trustline)',
    description: 'Open a 1000 USD trustline to the Bitstamp issuer.',
    category: 'legit',
    build: (account) =>
      buildTrustSet({ account, currency: 'USD', issuer: BITSTAMP_USD_ISSUER, value: '1000' }),
  },
  {
    id: 'adv-partial-payment',
    label: '⚠ Adversarial — partial payment (no DeliverMin)',
    description:
      'Payment with tfPartialPayment set and a large SendMax but no DeliverMin. Destination is you.',
    category: 'adversarial',
    expectedWalletBehavior:
      'Wallet must warn (partial payment, no minimum delivery) or reject; Amount is a ceiling, not guaranteed.',
    build: (account) => ({
      ...buildPayment({ account, destination: account, xrp: '1' }),
      Flags: TF_PARTIAL_PAYMENT,
      SendMax: xrpToDrops('1000'),
    }),
  },
  {
    id: 'adv-hidden-paths',
    label: '⚠ Adversarial — hidden Paths',
    description: 'Payment carrying a custom Paths array that reroutes how value is sourced. Destination is you.',
    category: 'adversarial',
    expectedWalletBehavior: 'Wallet must show that custom Paths are present.',
    build: (account) => ({
      ...buildPayment({ account, destination: account, xrp: '1' }),
      SendMax: { currency: 'USD', issuer: BITSTAMP_USD_ISSUER, value: '5' },
      Paths: [
        [{ currency: 'USD', issuer: BITSTAMP_USD_ISSUER }, { currency: 'XRP' }],
      ],
    }),
  },
]

export function getRippleExample(id: string): RippleExample | undefined {
  return rippleExamples.find((example) => example.id === id)
}
