import {
  buildOfferCreate,
  buildPayment,
  buildSelfSwapPayment,
  buildTrustSet,
  xrpToDrops,
} from './rippleTransactions'

// Presets exercise fields that must be visible before signature. They remain
// sign-only to prevent example payloads from changing live ledger state.

// tfPartialPayment: Amount becomes a ceiling, not a guaranteed delivery.
const TF_PARTIAL_PAYMENT = 131072

const BITSTAMP_USD_ISSUER = 'rvYAfWj5gh67oV6fW32ZzP3Aw4Eubs59B'
const GATEHUB_USD_ISSUER = 'rhub8VRN55s94qWKDv6jmDy1pUykJzF3wq'
const USD_TO_XRP_PATHS = [[{ currency: 'XRP' }]]
// Hops through GateHub USD before converting to XRP, while SendMax names Bitstamp —
// the path sources value differently than the visible fields imply.
const REROUTED_USD_TO_XRP_PATHS = [
  [{ currency: 'USD', issuer: GATEHUB_USD_ISSUER }, { currency: 'XRP' }],
]

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
    description:
      'Send 1 XRP to yourself. Sign-only by design: as bundled this is network-invalid (rippled rejects a plain self-payment as temREDUNDANT). Edit Destination to a real address to build a broadcastable payment.',
    category: 'legit',
    build: (account) => buildPayment({ account, destination: account, xrp: '1' }),
  },
  {
    id: 'selfSwap',
    label: 'Self cross-currency payment',
    description: 'Convert up to 1.5 USD (Bitstamp) into 1 XRP for your own account.',
    category: 'legit',
    build: (account) =>
      buildSelfSwapPayment({
        account,
        deliverXrp: '1',
        sendMax: { currency: 'USD', issuer: BITSTAMP_USD_ISSUER, value: '1.5' },
        paths: USD_TO_XRP_PATHS,
      }),
  },
  {
    id: 'selfSwapPathless',
    label: 'Self cross-currency payment (default paths)',
    description:
      'Convert up to 1.5 USD (Bitstamp) into 1 XRP with no explicit Paths field — the payment engine uses default path finding.',
    category: 'legit',
    build: (account) =>
      buildSelfSwapPayment({
        account,
        deliverXrp: '1',
        sendMax: { currency: 'USD', issuer: BITSTAMP_USD_ISSUER, value: '1.5' },
      }),
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
      ...buildSelfSwapPayment({
        account,
        deliverXrp: '1',
        sendMax: { currency: 'USD', issuer: BITSTAMP_USD_ISSUER, value: '1000' },
        paths: USD_TO_XRP_PATHS,
      }),
      Flags: TF_PARTIAL_PAYMENT,
    }),
  },
  {
    id: 'adv-hidden-paths',
    label: '⚠ Adversarial — hidden Paths',
    description:
      'Payment whose Paths reroute the conversion through a GateHub USD hop while SendMax names Bitstamp USD — value is sourced differently than the visible fields imply. Destination is you.',
    category: 'adversarial',
    expectedWalletBehavior:
      'Wallet must surface the custom Paths (the issuer hop differs from the SendMax issuer); hiding them hides the reroute.',
    build: (account) =>
      buildSelfSwapPayment({
        account,
        deliverXrp: '1',
        sendMax: { currency: 'USD', issuer: BITSTAMP_USD_ISSUER, value: '5' },
        paths: REROUTED_USD_TO_XRP_PATHS,
      }),
  },
]

export function getRippleExample(id: string): RippleExample | undefined {
  return rippleExamples.find((example) => example.id === id)
}
