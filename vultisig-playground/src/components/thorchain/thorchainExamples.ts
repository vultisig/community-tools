export const getThorchainExampleDirectMsgs = (signer: string) => ({
  singleSend: [
    {
      typeUrl: '/types.MsgSend',
      value: {
        fromAddress: signer || 'thor1...',
        toAddress: signer || 'thor1...',
        amount: [
          {
            amount: '1000',
            denom: 'rune',
          },
        ],
      },
    },
  ],
  multiSend: [
    {
      typeUrl: '/types.MsgSend',
      value: {
        fromAddress: signer || 'thor1...',
        toAddress: signer || 'thor1...',
        amount: [
          {
            amount: '1000',
            denom: 'rune',
          },
        ],
      },
    },
    {
      typeUrl: '/types.MsgSend',
      value: {
        fromAddress: signer || 'thor1...',
        toAddress: signer || 'thor1...',
        amount: [
          {
            amount: '2000',
            denom: 'rune',
          },
        ],
      },
    },
    {
      typeUrl: '/types.MsgSend',
      value: {
        fromAddress: signer || 'thor1...',
        toAddress: signer || 'thor1...',
        amount: [
          {
            amount: '3000',
            denom: 'rune',
          },
        ],
      },
    },
  ],
  deposit: [
    {
      typeUrl: '/types.MsgDeposit',
      value: {
        memo: 'secure-:ltc1qc56q990vzj3a89d544dvj28grrpxqq0pw64hq4',
        signer: signer || 'thor1...',
        coins: [
          {
            asset: {
              chain: 'LTC',
              symbol: 'LTC',
              ticker: 'LTC',
              synth: false,
              trade: false,
              secured: true,
            },
            decimals: 0,
            amount: '3000000',
          },
        ],
      },
    },
  ],
})
