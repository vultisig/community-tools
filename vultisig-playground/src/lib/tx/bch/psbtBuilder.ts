import * as bitcoin from '@shapeshiftoss/bitcoinjs-lib'
import { Buffer } from 'buffer'
import { Utxo } from '../btc/UtxoQueryClient'
import * as bchAddr from "bchaddrjs";

export interface PsbtInputConfig {
  txid: string
  vout: number
  hex: string
}

export interface PsbtOutputConfig {
  address: string
  amount: bigint
}

export interface PsbtConfig {
  inputs: PsbtInputConfig[]
  outputs: PsbtOutputConfig[]
  version?: number
  locktime?: number
  opReturnData?: string
}

export interface UtxoWithHex extends Utxo {
  hex: string
}

const bchNetwork = {
  name: "bitcoin cash",
  apiName: "abc",
  appName: "Bitcoin Cash",
  satoshi: 8,
  unit: "BCH",
  bitcoinjs: {
    bech32: "bc",
    bip32: {
      private: 76066276,
      public: {
        p2pkh: 76067358,
      },
    },
    messagePrefix: "Bitcoin Signed Message:",
    pubKeyHash: 0,
    scriptHash: 5,
    wif: 128,
  },
  sigHash: 0x41,
  isSegwitSupported: true,
  handleFeePerByte: true,
  additionals: ["abc"],
}

export class BchPsbtBuilder {
  private network: any

  constructor(network = bchNetwork) {
    this.network = network
  }

  public async buildPsbt(config: PsbtConfig): Promise<bitcoin.Psbt> {
    const psbt = new bitcoin.Psbt({ network: this.network.bitcoinjs })

    psbt.setVersion(config.version ?? 2)
    if (config.locktime && config.locktime > 0) {
      psbt.setLocktime(config.locktime)
    }

    for (const input of config.inputs) {
      if (!input.txid || !input.hex) {
        throw new Error('All inputs must have txid and hex')
      }

      psbt.addInput({
        hash: input.txid, 
        index: input.vout,
        nonWitnessUtxo: Buffer.from(input.hex, 'hex'),
      })
    }

    for (const output of config.outputs) {
      if (!output.address || output.amount === undefined) {
        throw new Error('All outputs must have address and amount')
      }

      let finalAddress = output.address;

      if (bchAddr.isCashAddress(output.address)) {
        finalAddress = bchAddr.toLegacyAddress(output.address);
      }

      psbt.addOutput({
        address: finalAddress,
        value: output.amount,
      })
    }

    if (config.opReturnData?.trim()) {
      const data = Buffer.from(config.opReturnData, 'utf-8')
      const embed = bitcoin.payments.embed({ data: [data] })
      const script = embed.output
      if (!script) {
        throw new Error('Unable to build OP_RETURN script')
      }
      psbt.addOutput({ script, value: BigInt(0) })
    }

    return psbt
  }

  public async buildPsbtFromUtxos(
    utxosWithHex: UtxoWithHex[],
    fromAddress: string,
    toAddress: string,
    amount: bigint,
    feeRate: bigint = BigInt(10),
    opReturnData?: string
  ): Promise<{ psbt: bitcoin.Psbt; selectedUtxos: Utxo[] }> {
    const selectedUtxos = this.selectUtxos(utxosWithHex, amount, feeRate)
    const totalInput = selectedUtxos.reduce((sum, utxo) => sum + utxo.value, BigInt(0))

    const estimatedFee = this.estimateFee(selectedUtxos.length, 2, feeRate)
    const change = totalInput - amount - estimatedFee

    const outputs: PsbtOutputConfig[] = [
      { address: toAddress, amount },
    ]

    if (change > BigInt(0)) {
      outputs.push({ address: fromAddress, amount: change })
    }

    const inputs: PsbtInputConfig[] = selectedUtxos.map((utxo) => ({
      txid: utxo.hash,
      vout: utxo.index,
      hex: utxo.hex,
    }))

    const psbt = await this.buildPsbt({
      inputs,
      outputs,
      opReturnData,
    })

    const selectedUtxosWithoutHex: Utxo[] = selectedUtxos.map(({ hex, ...utxo }) => utxo)

    return { psbt, selectedUtxos: selectedUtxosWithoutHex }
  }

  private selectUtxos(utxos: UtxoWithHex[], amount: bigint, feeRate: bigint): UtxoWithHex[] {
    const sortedUtxos = [...utxos].sort((a, b) => {
      if (a.value < b.value) return -1
      if (a.value > b.value) return 1
      return 0
    })

    let total = BigInt(0)
    const selected: UtxoWithHex[] = []

    for (const utxo of sortedUtxos) {
      selected.push(utxo)
      total += utxo.value

      const estimatedFee = this.estimateFee(selected.length, 2, feeRate)
      if (total >= amount + estimatedFee) {
        break
      }
    }

    const finalEstimatedFee = this.estimateFee(selected.length, 2, feeRate)
    if (total < amount + finalEstimatedFee) {
      throw new Error('Insufficient funds to cover amount and fees')
    }

    return selected
  }

  private estimateFee(inputCount: number, outputCount: number, feeRate: bigint): bigint {
    const baseTxSize = 10
    const inputSize = 148
    const outputSize = 34
    const totalSize = baseTxSize + inputCount * inputSize + outputCount * outputSize
    return BigInt(totalSize) * feeRate
  }
}

