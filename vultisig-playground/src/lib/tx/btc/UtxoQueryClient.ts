export type UtxoNetwork = 'BTC' | 'BCH' | 'DOGE' | 'LTC'

export interface Utxo {
  index: number
  hash: string
  value: bigint
}

export type UtxoWithHex = Utxo & { hex?: string }

type UtxoChainName = 'bitcoin' | 'bitcoincash' | 'dogecoin' | 'litecoin'

export function utxoNetworkTochain(network: UtxoNetwork): UtxoChainName {
  switch (network) {
    case 'BTC':
      return 'bitcoin'
    case 'BCH':
      return 'bitcoincash'
    case 'DOGE':
      return 'dogecoin'
    case 'LTC':
      return 'litecoin'
    default:
      throw new Error(`Unsupported UTXO network: ${network}`)
  }
}

export interface GraphQLUtxoResponse {
  oIndex: number
  oTxHash: string
  value: { value: string }
  scriptHex?: string
  oTxHex?: string
  isCoinbase?: boolean
  address?: string
}

export class UtxoQueryClient {
  private api = 'https://gql-router.xdefi.services/graphql'

  constructor(
    private network: UtxoNetwork,
    private address: string
  ) {}

  async fetch(): Promise<UtxoWithHex[]> {
    const query = `query GetUnspentTxOutputsV5($address: String!, $page: Int!) {
      ${utxoNetworkTochain(this.network)} {
        unspentTxOutputsV5(address: $address, page: $page) {
          oIndex
          oTxHash
          value {
            value
          }
          scriptHex
          oTxHex
          isCoinbase
          address
        }
      }
    }`

    return fetch(this.api, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'apollographql-client-name': 'docs-indexers-api',
        'apollographql-client-version': 'v1.0',
      },
      body: JSON.stringify({
        query,
        variables: { address: this.address, page: 0 },
      }),
    })
      .then((response) => response.json())
      .then((result) => {
        if (result.errors) {
          throw new Error(`GraphQL errors: ${JSON.stringify(result.errors)}`)
        }

        const chain = utxoNetworkTochain(this.network)
        const utxos = result.data?.[chain]?.unspentTxOutputsV5 as GraphQLUtxoResponse[] | undefined

        if (!utxos) {
          return []
        }

        return utxos.map(
          (x: GraphQLUtxoResponse): UtxoWithHex => ({
            value: BigInt(x.value.value),
            index: x.oIndex,
            hash: x.oTxHash,
            hex: x.oTxHex,
          })
        )
      })
  }
}

