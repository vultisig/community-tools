import assert from 'node:assert/strict'
import { describe, it } from 'node:test'
import { executeRippleTransaction, isPresetBroadcastBlocked } from './rippleSigningPolicy.ts'
import { buildSelfSwapPayment, xrpToDrops } from './rippleTransactions.ts'

const account = 'rExampleAccount'
const issuer = 'rExampleIssuer'

describe('xrpToDrops', () => {
  it('converts exact XRP precision to drops', () => {
    assert.equal(xrpToDrops('1.000001'), '1000001')
  })

  it('rejects precision below one drop', () => {
    assert.throws(() => xrpToDrops('1.0000001'), /up to 6 decimal places/)
  })
})

describe('buildSelfSwapPayment', () => {
  it('builds a cross-currency self-payment', () => {
    const sendMax = { currency: 'USD', issuer, value: '1.5' }
    const paths = [[{ currency: 'XRP' }]]

    assert.deepEqual(buildSelfSwapPayment({ account, deliverXrp: '1', sendMax, paths }), {
      TransactionType: 'Payment',
      Account: account,
      Destination: account,
      Amount: '1000000',
      SendMax: sendMax,
      Paths: paths,
    })
  })

  it('omits Paths entirely when none are provided', () => {
    const sendMax = { currency: 'USD', issuer, value: '1.5' }

    assert.deepEqual(buildSelfSwapPayment({ account, deliverXrp: '1', sendMax }), {
      TransactionType: 'Payment',
      Account: account,
      Destination: account,
      Amount: '1000000',
      SendMax: sendMax,
    })
  })

  it('rejects an explicitly-passed empty path set', () => {
    assert.throws(
      () => buildSelfSwapPayment({ account, deliverXrp: '1', sendMax: '1500000', paths: [] }),
      /must contain at least one non-empty path/,
    )
    assert.throws(
      () => buildSelfSwapPayment({ account, deliverXrp: '1', sendMax: '1500000', paths: [[]] }),
      /must contain at least one non-empty path/,
    )
  })
})

describe('isPresetBroadcastBlocked', () => {
  it('blocks broadcasting an unedited bundled preset', () => {
    assert.equal(isPresetBroadcastBlocked('submit', true), true)
  })

  it('allows sign-only presets and edited raw transactions', () => {
    assert.equal(isPresetBroadcastBlocked('sign', true), false)
    assert.equal(isPresetBroadcastBlocked('submit', false), false)
  })

  it('keeps submitTransaction unreachable for bundled presets', async () => {
    let submitCalls = 0
    const provider = {
      signTransaction: async () => ({ signature: 'signed' }),
      submitTransaction: async () => {
        submitCalls += 1
        return { hash: 'submitted' }
      },
    }

    await assert.rejects(
      executeRippleTransaction({
        mode: 'submit',
        isPresetSelected: true,
        transaction: { TransactionType: 'Payment' },
        provider,
      }),
      /Bundled examples are sign-only/,
    )
    assert.equal(submitCalls, 0)
  })
})
